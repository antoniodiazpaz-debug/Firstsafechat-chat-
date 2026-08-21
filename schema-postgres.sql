-- ═══════════════════════════════════════════════════════════════════════════
-- SecureChat — Postgres-Schema, selbst gehostet
-- ═══════════════════════════════════════════════════════════════════════════
-- Ausgelegt auf 10 000 Nutzer zum Start und 1 000 000 ohne Schemaänderung.
--
-- Die eine Entscheidung, die später nicht mehr nachzuholen ist:
-- envelopes ist nach Tagen partitioniert. Löschen wird damit zu DROP TABLE
-- (Millisekunden) statt DELETE über hunderte GB (Stunden Sperrzeit).
-- Bei 10 000 Nutzern merkt man keinen Unterschied. Bei 500 000 rettet es
-- den Betrieb.
--
--   psql -U postgres -d securechat -f schema.sql
-- ═══════════════════════════════════════════════════════════════════════════

create extension if not exists pgcrypto;
create extension if not exists pg_cron;      -- für das automatische Aufräumen

-- ───────────────────────────────────────────────────────────────────────────
-- NUTZER
-- ───────────────────────────────────────────────────────────────────────────
create table users (
  id            uuid primary key default gen_random_uuid(),
  name          text unique not null check (char_length(name) between 2 and 40),
  phone         text,
  avatar_path   text,                    -- Verweis auf R2, nicht das Bild selbst
  bio           text default '',
  pw_salt       text not null,
  pw_hash       text not null,
  ik_dh         jsonb not null,
  ik_sign       jsonb not null,
  uak           text,
  allow_sealed  boolean not null default true,
  quota_bytes   bigint not null default 52428800,   -- 50 MB Medienkontingent
  used_bytes    bigint not null default 0,
  last_seen     timestamptz not null default now(),
  created_at    timestamptz not null default now()
);
create index on users (lower(name));
create index on users (uak) where uak is not null;

create table sessions (
  token       text primary key,
  user_id     uuid not null references users(id) on delete cascade,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null
);
create index on sessions (user_id);
create index on sessions (expires_at);

-- ───────────────────────────────────────────────────────────────────────────
-- PREKEYS
-- ───────────────────────────────────────────────────────────────────────────
create table signed_prekeys (
  user_id    uuid primary key references users(id) on delete cascade,
  spk_id     integer not null,
  pub        jsonb not null,
  signature  text not null,
  created_at timestamptz not null default now()
);

create table one_time_prekeys (
  id          bigserial primary key,
  user_id     uuid not null references users(id) on delete cascade,
  opk_id      integer not null,
  pub         jsonb not null,
  consumed    boolean not null default false,
  consumed_at timestamptz,
  unique (user_id, opk_id)
);
-- Partieller Index: nur die unverbrauchten sind interessant
create index on one_time_prekeys (user_id, opk_id) where not consumed;

-- Bundle-Ausgabe. SKIP LOCKED ist der Grund, warum das eine Funktion ist:
-- Zwei gleichzeitige Abrufe müssen VERSCHIEDENE One-Time Prekeys bekommen.
create or replace function fetch_bundle(target uuid)
returns jsonb language plpgsql as $$
declare u users; s signed_prekeys; o one_time_prekeys;
begin
  select * into u from users where id = target;
  if not found then raise exception 'Unbekannter Nutzer'; end if;
  select * into s from signed_prekeys where user_id = target;
  if not found then raise exception 'Kein Prekey hinterlegt'; end if;

  select * into o from one_time_prekeys
    where user_id = target and not consumed
    order by opk_id limit 1 for update skip locked;
  if found then
    update one_time_prekeys set consumed = true, consumed_at = now() where id = o.id;
  end if;

  return jsonb_build_object(
    'userId', target, 'ikDH', u.ik_dh, 'ikSign', u.ik_sign,
    'spk', s.pub, 'spkId', s.spk_id, 'spkSig', s.signature,
    'spkCreatedAt', extract(epoch from s.created_at) * 1000,
    'opk', case when o is null then null else o.pub end,
    'opkId', case when o is null then null else o.opk_id end);
end $$;

-- ───────────────────────────────────────────────────────────────────────────
-- UMSCHLÄGE — nach Tagen partitioniert
-- ───────────────────────────────────────────────────────────────────────────
create table envelopes (
  id           uuid not null default gen_random_uuid(),
  sender_id    uuid,                     -- NULL bei Sealed Sender
  sealed       boolean not null default false,
  via_mix      boolean not null default false,
  recipient_id uuid not null,
  conv_id      text not null,
  group_id     uuid,
  kind         text not null default 'text',
  header       jsonb,
  ciphertext   text not null,
  gossip       jsonb,
  sent_at      timestamptz not null default now(),
  delivered_at timestamptz,
  acked        boolean not null default false,
  primary key (id, sent_at)
) partition by range (sent_at);

-- Partitionen für die nächsten Tage anlegen
create or replace function ensure_partitions(days_ahead int default 3)
returns void language plpgsql as $$
declare d date; part text;
begin
  for i in 0..days_ahead loop
    d := current_date + i;
    part := 'envelopes_' || to_char(d, 'YYYY_MM_DD');
    if not exists (select 1 from pg_class where relname = part) then
      execute format(
        'create table %I partition of envelopes for values from (%L) to (%L)',
        part, d, d + 1);
      -- Index nur auf dem, wonach wirklich gesucht wird
      execute format(
        'create index on %I (recipient_id) where not acked', part);
    end if;
  end loop;
end $$;

select ensure_partitions(3);

-- ───────────────────────────────────────────────────────────────────────────
-- MEDIEN — die Dateien liegen in R2, hier steht nur die Buchführung
-- ───────────────────────────────────────────────────────────────────────────
create table media_refs (
  path        text primary key,          -- UUID ohne Endung, kein Dateiname
  owner_id    uuid not null references users(id) on delete cascade,
  bytes       bigint not null,
  kind        text not null,             -- image | video | audio | file | avatar
  refs        integer not null default 1,-- wie viele Umschläge zeigen darauf
  permanent   boolean not null default false,  -- Profilbilder, markierte
  created_at  timestamptz not null default now(),
  expires_at  timestamptz                -- NULL = dauerhaft
);
create index on media_refs (expires_at) where not permanent;
create index on media_refs (owner_id);

-- Kontingent mitführen, damit niemand den Speicher vollschreibt
create or replace function media_quota_check()
returns trigger language plpgsql as $$
declare u users;
begin
  select * into u from users where id = new.owner_id for update;
  if u.used_bytes + new.bytes > u.quota_bytes then
    raise exception 'Speicherkontingent erschöpft (% von % Byte)',
      u.used_bytes, u.quota_bytes;
  end if;
  update users set used_bytes = used_bytes + new.bytes where id = new.owner_id;
  return new;
end $$;
create trigger media_quota before insert on media_refs
  for each row execute function media_quota_check();

create or replace function media_quota_release()
returns trigger language plpgsql as $$
begin
  update users set used_bytes = greatest(0, used_bytes - old.bytes)
    where id = old.owner_id;
  return old;
end $$;
create trigger media_release after delete on media_refs
  for each row execute function media_quota_release();

-- ───────────────────────────────────────────────────────────────────────────
-- GRUPPEN
-- ───────────────────────────────────────────────────────────────────────────
create table groups (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  avatar     text default '👥',
  owner_id   uuid not null references users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table group_members (
  group_id  uuid not null references groups(id) on delete cascade,
  user_id   uuid not null references users(id) on delete cascade,
  wrapped   text,
  is_admin  boolean not null default false,
  primary key (group_id, user_id)
);
create index on group_members (user_id);

-- ───────────────────────────────────────────────────────────────────────────
-- KEY TRANSPARENCY — append-only, per Trigger erzwungen
-- ───────────────────────────────────────────────────────────────────────────
create table kt_entries (
  idx        bigint primary key,
  user_id    uuid not null,
  key_x      text not null,
  key_y      text not null,
  version    integer not null,
  leaf_hash  text not null,
  added_at   timestamptz not null default now()
);
create index on kt_entries (user_id);

create table kt_sths (
  size      bigint primary key,
  root      text not null,
  ts        timestamptz not null default now(),
  signature text not null,
  cosigs    jsonb not null default '[]'
);

create or replace function kt_append_only()
returns trigger language plpgsql as $$
begin
  raise exception 'kt_entries ist append-only — % nicht erlaubt', tg_op;
end $$;
create trigger kt_no_update before update on kt_entries
  for each row execute function kt_append_only();
create trigger kt_no_delete before delete on kt_entries
  for each row execute function kt_append_only();

-- ───────────────────────────────────────────────────────────────────────────
-- AUFRÄUMEN
-- ───────────────────────────────────────────────────────────────────────────
-- Aufbewahrung: 7 Tage zum Start. Verlängern ist jederzeit möglich —
-- einfach RETENTION_DAYS erhöhen. Verkürzen wäre ein Datenverlust für
-- Nutzer, die sich darauf verlassen haben. Deshalb niedrig anfangen.
create table settings (key text primary key, value text not null);
insert into settings values ('retention_days', '7') on conflict do nothing;

create or replace function drop_old_partitions()
returns integer language plpgsql as $$
declare
  keep int := (select value::int from settings where key = 'retention_days');
  r record; n int := 0;
begin
  for r in
    select relname from pg_class c
      join pg_namespace ns on ns.oid = c.relnamespace
     where c.relkind = 'r'
       and ns.nspname = current_schema()
       -- Strikt: nur envelopes_JJJJ_MM_TT, damit z. B. envelopes_archive
       -- niemals versehentlich mitgelöscht wird
       and relname ~ '^envelopes_[0-9]{4}_[0-9]{2}_[0-9]{2}$'
       -- Nur echte Partitionen von envelopes, keine losen Tabellen
       and c.oid in (select inhrelid from pg_inherits
                      where inhparent = 'envelopes'::regclass)
       and to_date(right(relname, 10), 'YYYY_MM_DD') < current_date - keep
  loop
    execute format('drop table %I', r.relname);   -- Millisekunden, keine Sperre
    n := n + 1;
  end loop;
  return n;
end $$;

-- Verwaiste Mediendateien: in media_refs, aber kein Umschlag zeigt mehr darauf.
-- Gibt die Pfade zurück; das Löschen in R2 macht der Anwendungsdienst.
create or replace function orphaned_media(limit_n int default 1000)
returns table (path text, bytes bigint) language sql as $$
  select m.path, m.bytes from media_refs m
   where not m.permanent
     and (m.expires_at is not null and m.expires_at < now())
   limit limit_n;
$$;

create or replace function purge_sessions()
returns integer language plpgsql as $$
declare n int;
begin
  delete from sessions where expires_at < now();
  get diagnostics n = row_count; return n;
end $$;

-- Stündlich neue Partitionen, nächtlich aufräumen
select cron.schedule('partitions', '0 * * * *',  'select ensure_partitions(3)');
select cron.schedule('purge-parts', '15 3 * * *', 'select drop_old_partitions()');
select cron.schedule('purge-sess',  '30 3 * * *', 'select purge_sessions()');

-- ───────────────────────────────────────────────────────────────────────────
-- BEOBACHTUNG — was man im Betrieb wirklich braucht
-- ───────────────────────────────────────────────────────────────────────────
create or replace view v_health as
select
  (select count(*) from users)                                as users,
  (select count(*) from users where last_seen > now() - interval '5 min') as online,
  (select count(*) from envelopes where not acked)            as pending,
  (select count(*) from kt_entries)                           as log_size,
  (select coalesce(sum(bytes), 0) from media_refs)            as media_bytes,
  (select count(*) from pg_class where relname like 'envelopes\_%') as partitions,
  pg_size_pretty(pg_database_size(current_database()))        as db_size;
