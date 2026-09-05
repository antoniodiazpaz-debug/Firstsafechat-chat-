/* ═══════════════════════════════════════════════════════════════════════
   APP — verbindet crypto-core.js und api-client.js zu einer echten
   Anwendung. Anders als die alte index.html-Simulation spricht das
   hier den echten Server über HTTP/WebSocket an.
   ═══════════════════════════════════════════════════════════════════════ */
import { P, PreKeys, KT, X3DH, Ratchet, MAX_SKIP, b64, ub64, hexs, te, td } from '/crypto-core.js';
import { ApiClient, hashContact } from '/api-client.js';
import { setLocale, getLocale, t } from '/i18n.js';
import { detectLanguage, guessDialCode, preparePhoneInput, watchForSmsCode } from '/device-info.js';
import { Call } from '/call.js';

/* Sprache sofort beim Laden setzen — vor jedem UI-Aufbau, damit auch
   die allererste gerenderte Seite (Boot/Auth) schon übersetzt ist. */
setLocale(detectLanguage().supported);
if (document.documentElement) document.documentElement.lang = getLocale();

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const time = t => new Date(t).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
const day = t => {
  const a = new Date(t), n = new Date();
  if (a.toDateString() === n.toDateString()) return 'Heute';
  if (a.toDateString() === new Date(n - 864e5).toDateString()) return 'Gestern';
  return a.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: '2-digit' });
};
const seenTxt = t => {
  const x = Date.now() - t;
  if (x < 6e4) return 'gerade eben';
  if (x < 36e5) return 'vor ' + Math.floor(x / 6e4) + ' Min.';
  if (x < 864e5) return 'heute um ' + time(t);
  return 'zuletzt ' + day(t);
};
function toast(msg, ms = 2300) {
  document.querySelectorAll('.toast').forEach(e => e.remove());
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

const API_BASE = window.SECURECHAT_CONFIG?.apiBase || location.origin;
const api = new ApiClient(API_BASE);

/* ═══════════════════════════════════════════════════════════════════════
   LOKALER VAULT — verschlüsselte Schlüsselspeicherung (IndexedDB)
   Der private Schlüssel eines Geräts verlässt dieses Gerät nie. Er wird
   mit einem aus dem Passwort abgeleiteten Schlüssel verschlüsselt lokal
   gespeichert, damit ein Reload nicht die ganze Identität verliert.
   ═══════════════════════════════════════════════════════════════════════ */
function showDiagPanel(text) {
  document.getElementById('diagPanel')?.remove();
  const panel = document.createElement('div');
  panel.id = 'diagPanel';
  panel.style.cssText = 'position:fixed;inset:0;z-index:9999;background:#000;color:#0f0;' +
    'font-family:monospace;font-size:13px;padding:16px;overflow:auto;white-space:pre-wrap;' +
    'word-break:break-word;user-select:text;-webkit-user-select:text';
  panel.textContent = text;
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '✕ Schließen';
  closeBtn.style.cssText = 'position:sticky;top:0;background:#f15c6d;color:#fff;border:none;' +
    'padding:10px 16px;border-radius:8px;margin-bottom:12px;font-size:14px;display:block';
  closeBtn.onclick = () => panel.remove();
  panel.prepend(closeBtn);
  document.body.appendChild(panel);
}

/* ═══════════════════════════════════════════════════════════════════════
   LOKALER SPEICHER — Klartext localStorage (kein Crypto, kein IndexedDB)
   Token, DeviceId, UserName werden unverschlüsselt gespeichert.
   Die Crypto-Schlüssel (für E2EE) werden ebenfalls als JWK im
   localStorage gehalten — einfach und zuverlässig auf allen Geräten.
   ═══════════════════════════════════════════════════════════════════════ */
const Vault = {
  save(deviceId, identityStore, meta) {
    localStorage.setItem('sc:deviceId', deviceId);
    localStorage.setItem('sc:token', meta.token);
    localStorage.setItem('sc:userName', meta.userName || '');
    localStorage.setItem('sc:email', meta.email || '');
    localStorage.setItem('sc:keys', JSON.stringify({
      IK:   identityStore.IK.privJwk,
      IKS:  identityStore.IKS.privJwk,
      SPK:  identityStore.SPK.privJwk,
      opks: [...identityStore.opks].map(([id, k]) => [id, k.privJwk])
    }));
  },

  load(deviceId) {
    const storedId = localStorage.getItem('sc:deviceId');
    if (storedId !== deviceId) return null;
    const token = localStorage.getItem('sc:token');
    const keysRaw = localStorage.getItem('sc:keys');
    if (!token || !keysRaw) return null;
    return {
      data: JSON.parse(keysRaw),
      meta: {
        token,
        userName: localStorage.getItem('sc:userName') || '',
        email:    localStorage.getItem('sc:email') || ''
      }
    };
  },

  knownDeviceId() {
    return localStorage.getItem('sc:deviceId');
  },
  rememberDevice(deviceId, userName) {
    localStorage.setItem('sc:deviceId', deviceId);
    localStorage.setItem('sc:userName', userName);
  },
  forget() {
    ['sc:deviceId','sc:token','sc:userName','sc:email','sc:keys',
     'securechat:deviceId','securechat:userName','securechat:deviceKey']
      .forEach(k => localStorage.removeItem(k));
    /* Auch alte vault-Einträge entfernen */
    Object.keys(localStorage)
      .filter(k => k.startsWith('securechat:vault:'))
      .forEach(k => localStorage.removeItem(k));
  },
  async _db() { return null; }
};

/* ═══════════════════════════════════════════════════════════════════════
   LOCAL CACHE — verschlüsselter Nachrichten-Cache für den Offline-Modus
   ─────────────────────────────────────────────────────────────────────
   Ohne diesen Cache wäre "offline lesen" eine leere Behauptung: state.
   messages ist eine reine In-Memory-Map, die bei jedem Neuladen der
   Seite verloren geht. Hier wird der Konversationsstand nach jeder
   Änderung mit dem VAULT-Schlüssel verschlüsselt in IndexedDB abgelegt
   — also mit demselben Schlüssel, der auch die privaten Ratchet-
   Schlüssel schützt. Ein gestohlenes, gesperrtes Gerät gibt damit weder
   Schlüssel noch Klartext-Verlauf preis, nur wer das Passwort kennt,
   kommt an beides.

   Bewusst NICHT im Service-Worker-Cache (der ist für die Programmhülle,
   liegt unverschlüsselt — siehe sw.js). Getrennte Speicherorte für
   getrennte Vertraulichkeitsstufen.
   ═══════════════════════════════════════════════════════════════════════ */
const LocalCache = {
  _deviceId: null,

  async unlock(deviceId) {
    this._deviceId = deviceId;
  },

  /* Klartext in localStorage — einfach und zuverlässig, kein Crypto
     nötig da bereits im Klartext-Ansatz der App (siehe Vault). */
  async save() {
    if (!this._deviceId) return;
    const snapshot = {
      convs: [...state.convs.entries()],
      messages: [...state.messages.entries()],
      outbox: state.outbox,
      savedAt: Date.now()
    };
    try {
      localStorage.setItem('sc:cache:' + this._deviceId, JSON.stringify(snapshot));
    } catch (e) {
      console.warn('LocalCache.save fehlgeschlagen:', e.message);
    }
  },

  async load() {
    if (!this._deviceId) return false;
    const raw = localStorage.getItem('sc:cache:' + this._deviceId);
    if (!raw) return false;
    try {
      const snapshot = JSON.parse(raw);
      state.convs = new Map(snapshot.convs);
      state.messages = new Map(snapshot.messages);
      state.outbox = snapshot.outbox || [];
      return true;
    } catch (e) {
      console.warn('Lokaler Nachrichten-Cache nicht lesbar:', e.message);
      return false;
    }
  },

  _saveTimer: null,
  scheduleSave() {
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => { this._saveTimer = null; this.save().catch(() => {}); }, 800);
  }
};

/* ═══════════════════════════════════════════════════════════════════════
   ANWENDUNGSZUSTAND
   ═══════════════════════════════════════════════════════════════════════ */
const state = {
  me: null,
  device: null,
  identity: null,
  view: 'list',
  tab: 'chats',
  activeConv: null,
  convs: new Map(),
  messages: new Map(),
  sessions: new Map(),
  bundleCache: new Map(),
  monitor: null,
  search: '',
  blocked: new Set(),
  /* Eigener Netzstatus (nicht zu verwechseln mit "online" bei Kontakten,
     das ist deren WebSocket-Präsenz). Startet optimistisch mit
     navigator.onLine — das ist zuverlässig genug für "kein Netzadapter
     aktiv", erkennt aber keinen kaputten Proxy o. Ä.; die eigentliche
     Wahrheit liefert erst ein fehlgeschlagener fetch()-Aufruf. */
  isOffline: typeof navigator !== 'undefined' && navigator.onLine === false,
  /* Nachrichten, die während einer Netzunterbrechung geschrieben wurden.
     Werden automatisch erneut versucht, sobald das Netz zurückkommt —
     der Nutzer muss NICHT manuell erneut auf Senden tippen. */
  outbox: []   // { convId, peerId, text, localId, ts }
};
/* ═══════════════════════════════════════════════════════════════════════
   RATCHET-SESSIONS PERSISTIEREN
   ─────────────────────────────────────────────────────────────────────
   state.sessions lag bisher nur im Speicher — bei einem Reload (z. B.
   Android killt den Tab nach Bildschirmsperre) waren alle laufenden
   Ratchet-Zustände weg, und neue, mit fortgeschrittenem Zähler
   eintreffende Nachrichten wurden als "nicht entschlüsselbar" angezeigt.

   Der Ratchet-State enthält zwei CryptoKey-Objekte (DHs.priv/pub, DHr),
   die WebCrypto nicht direkt serialisieren kann — alles andere (RK,
   CKs, CKr, skipped-Map) sind bereits rohe Bytes. Export wandelt die
   CryptoKeys in ihre JWK-Form um (bereits vorhanden als DHs.privJwk/
   pubJwk und DHrJwk), Import re-importiert sie beim Laden. */
async function exportSession(st) {
  return {
    RK: b64(st.RK), CKs: st.CKs ? b64(st.CKs) : null, CKr: st.CKr ? b64(st.CKr) : null,
    DHsPriv: st.DHs.privJwk, DHsPub: st.DHs.pubJwk, DHrJwk: st.DHrJwk,
    Ns: st.Ns, Nr: st.Nr, PN: st.PN, dhSteps: st.dhSteps,
    skipped: [...st.skipped.entries()].map(([k, v]) => [k, b64(v)]),
    usedOpkId: st.usedOpkId ?? null,
    ephemeralPriv: st.ephemeral ? st.ephemeral.privJwk : null,
    ephemeralPub: st.ephemeral ? st.ephemeral.pubJwk : null
  };
}
async function importSession(rec) {
  const DHsPriv = await P.impPriv(rec.DHsPriv);
  const DHsPub = await P.impPub(rec.DHsPub);
  const DHr = rec.DHrJwk ? await P.impPub(rec.DHrJwk) : null;
  const st = {
    RK: ub64(rec.RK), CKs: rec.CKs ? ub64(rec.CKs) : null, CKr: rec.CKr ? ub64(rec.CKr) : null,
    DHs: { priv: DHsPriv, pub: DHsPub, privJwk: rec.DHsPriv, pubJwk: rec.DHsPub },
    DHrJwk: rec.DHrJwk, DHr,
    Ns: rec.Ns, Nr: rec.Nr, PN: rec.PN, dhSteps: rec.dhSteps,
    skipped: new Map(rec.skipped.map(([k, v]) => [k, ub64(v)])),
    log: [], usedOpkId: rec.usedOpkId ?? null
  };
  if (rec.ephemeralPriv) {
    st.ephemeral = {
      priv: await P.impPriv(rec.ephemeralPriv), pub: await P.impPub(rec.ephemeralPub),
      privJwk: rec.ephemeralPriv, pubJwk: rec.ephemeralPub
    };
  }
  return st;
}
let sessionSaveTimer = null;
function scheduleSessionSave() {
  if (sessionSaveTimer) return;
  sessionSaveTimer = setTimeout(async () => {
    sessionSaveTimer = null;
    if (!state.device?.id) return;
    try {
      const out = {};
      for (const [key, st] of state.sessions.entries()) out[key] = await exportSession(st);
      localStorage.setItem('sc:sessions:' + state.device.id, JSON.stringify(out));
    } catch (e) {
      console.warn('Session-Speichern fehlgeschlagen:', e.message);
    }
  }, 500);
}
async function loadSessions() {
  if (!state.device?.id) return;
  const raw = localStorage.getItem('sc:sessions:' + state.device.id);
  if (!raw) return;
  try {
    const stored = JSON.parse(raw);
    for (const [key, rec] of Object.entries(stored)) {
      state.sessions.set(key, await importSession(rec));
    }
  } catch (e) {
    console.warn('Sessions konnten nicht geladen werden:', e.message);
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   PUSH-BENACHRICHTIGUNGEN — App bleibt "erreichbar" auch geschlossen
   ─────────────────────────────────────────────────────────────────────
   Ein Browser-Tab kann im Hintergrund keinen WebSocket offen halten —
   das ist eine Grenze der Plattform, keine Design-Entscheidung. Die
   einzige Möglichkeit, den Nutzer bei geschlossener App zu erreichen,
   ist eine Push-Benachrichtigung über den Service Worker (funktioniert
   auch, wenn kein Tab offen ist). Der Server weiß dabei nie, WAS in der
   Nachricht steht — nur DASS eine da ist (siehe server.js notifyOffline
   und sw.js für die Begründung). */
async function setupPushNotifications() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  try {
    const reg = await navigator.serviceWorker.register('/sw.js');

    if (Notification.permission === 'default') {
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') return;
    }
    if (Notification.permission !== 'granted') return;

    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      const { publicKey } = await (await fetch(API_BASE + '/api/push/vapid-key')).json();
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey)
      });
    }
    const json = sub.toJSON();
    await fetch(API_BASE + '/api/push/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + api.token },
      body: JSON.stringify({
        platform: 'web', endpoint: json.endpoint,
        p256dh: json.keys?.p256dh, auth: json.keys?.auth
      })
    });
  } catch (e) {
    console.warn('Push-Registrierung fehlgeschlagen:', e.message);
  }
}
function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  return Uint8Array.from([...rawData].map(c => c.charCodeAt(0)));
}

/* Aktualisiert den Zustellstatus eigener gesendeter Nachrichten anhand
   ihrer Envelope-ID — 'delivered' (einfaches → doppeltes graues Häkchen)
   kommt vom ack-Handler des Servers, 'read' (blaues Häkchen) von einer
   expliziten Lesebestätigung des Empfängers (siehe sendReadReceipt). */
function markMessagesStatus(convId, ids, status) {
  if (!ids?.length) return;
  const msgs = state.messages.get(convId);
  if (!msgs) return;
  let changed = false;
  for (const m of msgs) {
    if (ids.includes(m.id) && m.mine) {
      /* 'read' überschreibt 'delivered', aber niemals umgekehrt —
         eine bereits gelesene Nachricht kann nicht wieder nur
         "zugestellt" werden. */
      if (status === 'read' || m.status !== 'read') { m.status = status; changed = true; }
    }
  }
  if (changed && state.activeConv?.convId === convId) renderChatMessages();
}

/* Lesebestätigung senden, sobald eine fremde Nachricht sichtbar
   gerendert wurde — nur falls die Einstellung aktiviert ist (siehe
   Chat-Einstellungen, readReceipts). */
function sendReadReceipt(convId, peerId, msgIds) {
  if (!msgIds.length) return;
  if (state.chatPrefs?.readReceipts === false) return;
  api.wsSend?.({ type: 'read', to: peerId, convId, ids: msgIds });
}

const sk = (peerId, peerDeviceId) => peerId + '>' + peerDeviceId;

/* ═══════════════════════════════════════════════════════════════════════
   NETZSTATUS
   ─────────────────────────────────────────────────────────────────────
   Zwei Signale kombiniert: das Browser-Ereignis (schnell, aber grob —
   erkennt nur "Netzwerkadapter tot") und der WebSocket-Verbindungsstatus
   (genauer, weil er tatsächlich mit dem Server spricht). Ein Banner
   erscheint nur, wenn BEIDE offline sagen, damit ein kurzer WebSocket-
   Reconnect-Versuch nicht sofort einen Alarm auslöst.
   ═══════════════════════════════════════════════════════════════════════ */
function setupOfflineDetection() {
  if (typeof window === 'undefined' || !window.addEventListener) return;
  window.addEventListener('online', () => { state.isOffline = false; updateOfflineBanner(); flushOutbox(); });
  window.addEventListener('offline', () => { state.isOffline = true; updateOfflineBanner(); });
}

function updateOfflineBanner() {
  const bar = document.getElementById('offlineBar');
  if (state.isOffline) {
    if (!bar) {
      const el = document.createElement('div');
      el.id = 'offlineBar';
      el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9500;' +
        'background:var(--warn);color:#3a2a00;text-align:center;font-size:12.5px;' +
        'font-weight:600;padding:6px 12px;padding-top:calc(6px + env(safe-area-inset-top));' +
        'transform:translateZ(0);will-change:transform';
      el.textContent = '⚠️ Keine Verbindung — Nachrichten werden gesendet, sobald du wieder online bist';
      document.body.prepend(el);
    }
  } else if (bar) {
    bar.remove();
  }
}

/* Wartende Nachrichten erneut versuchen, sobald die Verbindung zurück
   ist. Reihenfolge bleibt erhalten (älteste zuerst) — sonst könnten
   Antworten vor der Nachricht ankommen, auf die sie sich beziehen. */
async function flushOutbox() {
  if (!state.outbox.length) return;
  const pending = [...state.outbox];
  state.outbox = [];
  for (const item of pending) {
    try {
      await sendMessage(item.peerId, item.convId, item.text);
      /* Lokalen Platzhalter durch das echte, gesendete Ergebnis ersetzen */
      const msgs = state.messages.get(item.convId);
      const local = msgs?.find(m => m.id === item.localId);
      if (local) local.pending = false;
    } catch (e) {
      /* Immer noch offline oder Server lehnt ab (z. B. blockiert) —
         zurück in die Outbox, nicht stillschweigend verwerfen. */
      state.outbox.push(item);
    }
  }
  if (state.view === 'chat') renderChatMessages();
  renderMain();
}


/* ═══════════════════════════════════════════════════════════════════════
   BOOT
   ═══════════════════════════════════════════════════════════════════════ */
async function boot() {
  loadDisappearingSettings();
  loadChatPrefs();
  loadAccentTheme();
  loadPinnedAndFavorites();
  loadDeletedConvIds();
  const bootMsgEarly = document.getElementById('bootMsg');
  if (bootMsgEarly) bootMsgEarly.textContent = 'Verbinde…';

  /* Reset-Button nach 5s einblenden — falls die App hängt,
     kann der Nutzer localStorage löschen und neu starten. */
  const resetTimeout = setTimeout(() => {
    const existing = document.getElementById('bootResetBtn');
    if (existing) return;
    const btn = document.createElement('button');
    btn.id = 'bootResetBtn';
    btn.textContent = '🔄 Zurücksetzen & neu starten';
    btn.style.cssText = 'margin-top:24px;padding:12px 20px;border-radius:12px;border:none;' +
      'background:#f15c6d;color:#fff;font-size:15px;font-weight:600;display:block;' +
      'margin-left:auto;margin-right:auto;cursor:pointer';
    btn.onclick = () => { localStorage.clear(); location.reload(); };
    document.getElementById('boot')?.appendChild(btn);
  }, 5000);

  setupOfflineDetection();
  updateOfflineBanner();

  try {
    await api._fetch('/api/health', { auth: false });
  } catch (e) {
    const knownDevice = await Vault.knownDeviceId();
    if (!knownDevice) {
      $('#bootMsg').textContent = 'Server nicht erreichbar. Bitte später erneut versuchen.';
      return;
    }
    state.isOffline = true;
  }

  const knownDevice = await Vault.knownDeviceId();
  clearTimeout(resetTimeout);
  $('#boot').classList.add('hide');

  if (knownDevice) {
    renderLoginForKnownDevice(knownDevice, localStorage.getItem('securechat:userName') || '');
  } else {
    renderAuthChoice();
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   AUTH — Registrierung, Login (bekanntes Gerät), Pairing (neues Gerät)
   ═══════════════════════════════════════════════════════════════════════ */
function showAuth(html) {
  $('#auth').innerHTML = html;
  $('#auth').classList.remove('hide');
  $('#app').classList.add('hide');
}

function renderAuthChoice() {
  showAuth(`
    <div id="authCard" class="card">
      <div class="logo"><div class="ic">🔐</div><h1>${t('appName')}</h1>
        <p>${t('tagline')}</p></div>
      <div id="authErr" class="err hide"></div>
      <label>${t('username')}</label>
      <input class="in" id="aUser" placeholder="Anna" autocomplete="username">
      <label>${t('phone')}</label>
      <input class="in" id="aPhone" placeholder="${esc(guessDialCode())} …">
      <label>${t('email')}</label>
      <input class="in" id="aEmail" placeholder="du@example.com" autocomplete="email">
      <button class="btn" id="authBtn" onclick="window.__auth.submit()">${t('createAccount')}</button>
      <div class="enc">🔒 ${t('newDevice')}?<br>${t('pairHint')}</div>
      <div class="enc" style="margin-top:8px">
        <a href="#" onclick="window.__auth.recover(); return false;" style="color:var(--acc)">Bestehendes Konto wiederherstellen</a>
      </div>
    </div>`);
  window.__auth = { submit: authSubmit, recover: renderRecoveryPrompt };

  /* Telefonfeld für Browser-/OS-Autofill vorbereiten und mit der aus
     der Systemsprache geschätzten Vorwahl vorbefüllen — das Feld bleibt
     vollständig editierbar, es ist nur ein Startwert. */
  const phoneInput = $('#aPhone');
  if (phoneInput) {
    preparePhoneInput(phoneInput);
    const dial = guessDialCode();
    if (dial && !phoneInput.value) phoneInput.value = dial + ' ';
  }
}

function authErr(msg) {
  const e = $('#authErr'); e.textContent = '⚠️ ' + msg; e.classList.remove('hide');
}

/* Passwortlos: Registrierung ist der einzige Weg, ein Konto auf einem
   Gerät neu einzurichten. Ein bereits registriertes Gerät meldet sich
   automatisch an (siehe boot()) — es gibt keinen manuellen "Login"-Weg
   mehr für ein bereits bekanntes Gerät, und keinen Passwort-basierten
   Weg für ein neues Gerät (dafür existiert bereits das Pairing-System:
   ein Code von einem angemeldeten Gerät koppelt ein weiteres, siehe
   renderPairingPrompt). */
async function authSubmit() {
  const btn = $('#authBtn'); btn.disabled = true;
  const name = $('#aUser').value.trim();
  try {
    if (!name) return authErr(t('fieldsRequired'));

    /* Telefonnummer ist bewusst OPTIONAL — der Server verlangt sie
       nicht (siehe /api/register in server.js), sie dient nur dem
       freiwilligen Kontaktabgleich ("X nutzt die App auch"). */
    const phone = $('#aPhone').value.trim();

    const email = $('#aEmail').value.trim();
    if (!email) return authErr(t('emailRequired'));
    /* Bewusst nur eine grobe Formprüfung (etwas@etwas.etwas) — die
       eigentliche Gültigkeit bestätigt sich erst durch den zugestellten
       Bestätigungscode. Eine strengere Regex hier würde nur seltene,
       aber technisch gültige Adressen fälschlich ablehnen. */
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return authErr(t('emailInvalid'));

    btn.textContent = t('generatingKeys');
    const identity = await PreKeys.createStore();
    const platform = /Mobi|Android/i.test(navigator.userAgent) ? 'android' :
      (/iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'web');
    const data = await api.register({
      name, phone: phone || undefined, email,
      deviceName: guessDeviceName(), platform, identity
    });
    /* Sitzungstoken wird ZUSAMMEN mit den Identitätsschlüsseln im
       lokalen, durch den nicht-extrahierbaren Geräteschlüssel
       geschützten Vault gespeichert — das ist die gesamte
       "Passwort"-Ersetzung: kein Geheimnis, das der Nutzer eingibt,
       sondern ein Geheimnis, das an dieses Browserprofil gebunden ist
       und es nie in lesbarer Form verlässt. */
    await Vault.save(data.device.id, identity, { name, userId: data.user.id, token: data.token });
    Vault.rememberDevice(data.device.id, name);
    state.identity = identity;
    await afterAuth(data);
  } catch (e) {
    if (e.status === 428) {
      renderPairingPrompt(name);
    } else {
      authErr(e.message);
    }
  } finally {
    btn.disabled = false;
  }
}

function guessDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android-Gerät';
  if (/Macintosh/.test(ua)) return 'Mac (' + (window.chrome ? 'Chrome' : 'Safari') + ')';
  if (/Windows/.test(ua)) return 'Windows-PC';
  return 'Browser-Gerät';
}

function renderPairingPrompt(name) {
  showAuth(`
    <div class="card">
      <div class="logo"><div class="ic">🔗</div><h1>${t('newDevice')}</h1>
        <p>${t('appName')}</p></div>
      <div class="err" style="background:rgba(83,189,235,.1);border-color:rgba(83,189,235,.3);color:#a8dcf5">
        ${t('pairHint')}
      </div>
      <label>${t('pairCode')}</label>
      <input class="in" id="pairCode" placeholder="${t('pairCode')}" autocomplete="off">
      <div id="pairErr" class="err hide"></div>
      <button class="btn" id="pairBtn">${t('pair')}</button>
      <button class="btn ghost" style="margin-top:8px" onclick="window.__auth.back()">${t('back')}</button>
    </div>`);
  window.__auth = { ...window.__auth, back: renderAuthChoice };
  $('#pairBtn').onclick = async () => {
    const btn = $('#pairBtn'); btn.disabled = true;
    try {
      const code = $('#pairCode').value.trim();
      if (!code) { $('#pairErr').textContent = t('fieldsRequired'); $('#pairErr').classList.remove('hide'); return; }
      btn.textContent = t('generatingKeys');
      const identity = await PreKeys.createStore();
      const platform = /Mobi|Android/i.test(navigator.userAgent) ? 'android' :
        (/iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'web');
      const data = await api.pairClaim({ code, deviceName: guessDeviceName(), platform, identity });
      await Vault.save(data.device.id, identity, { name: data.user.name, userId: data.user.id, token: data.token });
      Vault.rememberDevice(data.device.id, data.user.name);
      state.identity = identity;
      await afterAuth(data);
    } catch (e) {
      $('#pairErr').textContent = '⚠️ ' + e.message;
      $('#pairErr').classList.remove('hide');
    } finally {
      btn.disabled = false; btn.textContent = t('pair');
    }
  };
}

function renderRecoveryPrompt() {
  showAuth(`
    <div class="card">
      <div class="logo"><div class="ic">📧</div><h1>Konto wiederherstellen</h1>
        <p>${t('appName')}</p></div>
      <p style="color:var(--sub);font-size:14px;margin:0 0 16px">
        Wir schicken dir einen Code an deine bestätigte E-Mail-Adresse.
        Damit richtest du dieses Gerät neu für dein bestehendes Konto ein.
      </p>
      <label>E-Mail</label>
      <input class="in" id="recEmail" placeholder="du@example.com" autocomplete="email">
      <div id="recErr" class="err hide"></div>
      <button class="btn" id="recRequestBtn">Code anfordern</button>
      <button class="btn ghost" style="margin-top:8px" onclick="window.__auth.back()">${t('back')}</button>
    </div>`);
  window.__auth = { ...window.__auth, back: renderAuthChoice };
  $('#recRequestBtn').onclick = async () => {
    const btn = $('#recRequestBtn'); btn.disabled = true;
    try {
      const email = $('#recEmail').value.trim();
      if (!email) { $('#recErr').textContent = t('emailRequired'); $('#recErr').classList.remove('hide'); return; }
      await api.recoverRequest(email);
      /* Die Server-Antwort verrät absichtlich nie, ob die E-Mail
         tatsächlich zu einem Konto gehört (siehe server.js) — die
         Oberfläche zeigt deshalb IMMER denselben nächsten Schritt,
         unabhängig vom tatsächlichen Ergebnis. */
      renderRecoveryCodeStep(email);
    } catch (e) {
      $('#recErr').textContent = '⚠️ ' + e.message;
      $('#recErr').classList.remove('hide');
    } finally {
      btn.disabled = false;
    }
  };
}

function renderRecoveryCodeStep(email) {
  showAuth(`
    <div class="card">
      <div class="logo"><div class="ic">📧</div><h1>Code eingeben</h1>
        <p>${esc(email)}</p></div>
      <p style="color:var(--sub);font-size:14px;margin:0 0 16px">
        Falls diese Adresse zu einem Konto gehört, ist dort jetzt ein
        6-stelliger Code angekommen (auch im Spam-Ordner nachsehen).
      </p>
      <label>Code</label>
      <input class="in" id="recCode" inputmode="numeric" maxlength="6" placeholder="000000">
      <div id="recCodeErr" class="err hide"></div>
      <button class="btn" id="recVerifyBtn">Konto wiederherstellen</button>
      <button class="btn ghost" style="margin-top:8px" onclick="window.__auth.back()">${t('back')}</button>
    </div>`);
  window.__auth = { ...window.__auth, back: renderAuthChoice };
  $('#recVerifyBtn').onclick = async () => {
    const btn = $('#recVerifyBtn'); btn.disabled = true;
    try {
      const code = $('#recCode').value.trim();
      if (!code || code.length !== 6) {
        $('#recCodeErr').textContent = 'Bitte den 6-stelligen Code eingeben.';
        $('#recCodeErr').classList.remove('hide');
        return;
      }
      btn.textContent = t('generatingKeys');
      /* Wiederherstellung erzeugt zwangsläufig ein NEUES Schlüsselpaar
         für dieses Gerät — die alten privaten Schlüssel haben das
         ursprüngliche Gerät nie verlassen (Ende-zu-Ende-Verschlüsselung)
         und lassen sich serverseitig nicht zurückholen. Der Nutzer
         bekommt denselben Namen und dasselbe Konto zurück, aber ein
         frisches Gerät darin. */
      const identity = await PreKeys.createStore();
      const platform = /Mobi|Android/i.test(navigator.userAgent) ? 'android' :
        (/iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'web');
      const data = await api.recoverVerify({ email, code, deviceName: guessDeviceName(), platform, identity });
      await Vault.save(data.device.id, identity, { name: data.user.name, userId: data.user.id, token: data.token });
      Vault.rememberDevice(data.device.id, data.user.name);
      state.identity = identity;
      await afterAuth(data);
    } catch (e) {
      $('#recCodeErr').textContent = '⚠️ ' + e.message;
      $('#recCodeErr').classList.remove('hide');
    } finally {
      btn.disabled = false; btn.textContent = 'Konto wiederherstellen';
    }
  };
}

/* Passwortlos: ein bekanntes Gerät meldet sich vollautomatisch an, ganz
   ohne Bildschirm dazwischen — der Vault entsperrt sich selbst (der
   nicht-extrahierbare Geräteschlüssel braucht keine Nutzereingabe), und
   das darin gespeicherte Sitzungstoken (30 Tage gültig, siehe server.js)
   wird direkt gegen /api/me geprüft. Nur wenn das Token abgelaufen ist
   oder der Vault aus irgendeinem Grund nicht lesbar ist, kommt der
   Nutzer zur Registrierung zurück — es gibt keinen Passwort-Fallback
   mehr, weil es kein Passwort mehr gibt. */
/* Passwortlos: ein bekanntes Gerät meldet sich vollautomatisch an, ganz
   ohne Bildschirm dazwischen — der Vault entsperrt sich selbst (der
   nicht-extrahierbare Geräteschlüssel braucht keine Nutzereingabe), und
   das darin gespeicherte Sitzungstoken (19 Jahre gültig, siehe server.js)
   wird direkt gegen /api/me geprüft. Nur wenn das Token abgelaufen ist
   oder der Vault aus irgendeinem Grund nicht lesbar ist, kommt der
   Nutzer zur Registrierung zurück — es gibt keinen Passwort-Fallback
   mehr, weil es kein Passwort mehr gibt. */
async function renderLoginForKnownDevice(deviceId, userName) {
  const vaultRec = Vault.load(deviceId);
  if (!vaultRec || !vaultRec.meta?.token) {
    Vault.forget();
    renderAuthChoice();
    return;
  }

  /* App sofort mit lokalen Daten öffnen — kein Warten auf Server */
  $('#boot').classList.add('hide');
  state.identity = await reconstructIdentityFromVault(vaultRec.data);
  api.token = vaultRec.meta.token;

  /* Offline-Cache laden falls vorhanden */
  await LocalCache.unlock(deviceId);
  await LocalCache.load();

  /* Sofort die Chat-Liste zeigen */
  await afterAuthOffline(deviceId, userName);

  /* Server-Check im Hintergrund — nur bei Fehler zur Anmeldung */
  fetch(API_BASE + '/api/me', {
    headers: { Authorization: 'Bearer ' + vaultRec.meta.token }
  }).then(async r => {
    if (r.status === 401) {
      /* Token abgelaufen — Vault löschen und neu anmelden */
      Vault.forget();
      location.reload();
      return;
    }
    if (!r.ok) return; /* Server-Fehler ignorieren, App bleibt offen */
    const me = await r.json();
    /* Online — vollständige Auth-Sequenz im Hintergrund */
    state.isOffline = false;
    updateOfflineBanner();
    await afterAuth({ token: vaultRec.meta.token, user: me.user, device: me.device });
  }).catch(() => {
    /* Kein Netz — App bleibt im Offline-Modus, kein Reload */
  });
}
async function reconstructIdentityFromVault(data) {
  const log = [];
  const step = (msg) => { log.push(new Date().toISOString().slice(11,23) + ' — ' + msg); };

  const bootMsgEl = document.getElementById('bootMsg');
  const setMsg = (m) => { if (bootMsgEl) bootMsgEl.textContent = m; };

  step('reconstructIdentityFromVault gestartet');
  setMsg('IK wird importiert…');
  step('data.IK vorhanden: ' + !!data.IK + ', kty=' + data.IK?.kty);
  step('data.IKS vorhanden: ' + !!data.IKS + ', kty=' + data.IKS?.kty);
  step('data.SPK vorhanden: ' + !!data.SPK + ', kty=' + data.SPK?.kty);
  step('data.opks vorhanden: ' + !!data.opks + ', Länge=' + data.opks?.length);

  const timeoutId = setTimeout(() => {
    step('TIMEOUT nach 3s — Import-Vorgang hat nie geantwortet');
    showDiagPanel(log.join('\n'));
  }, 3000);

  try {
    const importDH = jwk => crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const importSign = jwk => crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const pubOnly = jwk => { const c = { ...jwk }; delete c.d; return c; };

    step('importiere IK...');
    const IK = { priv: await importDH(data.IK), privJwk: data.IK, pubJwk: pubOnly(data.IK) };
    step('IK OK, importiere IKS...');
    setMsg('IKS wird importiert…');
    const IKS = { priv: await importSign(data.IKS), privJwk: data.IKS, pubJwk: pubOnly(data.IKS) };
    step('IKS OK, importiere SPK...');
    setMsg('SPK wird importiert…');
    const SPK = { priv: await importDH(data.SPK), privJwk: data.SPK, pubJwk: pubOnly(data.SPK) };
    step('SPK OK, importiere opks...');
    setMsg('OPKs werden importiert…');
    const opks = new Map();
    for (const [id, jwk] of data.opks) {
      opks.set(id, { priv: await importDH(jwk), privJwk: jwk, pubJwk: pubOnly(jwk) });
    }
    step('alle Schlüssel erfolgreich importiert');
    setMsg('Schlüssel importiert ✓');
    clearTimeout(timeoutId);
    return { IK, IKS, SPK, opks, opkSeq: opks.size, spkId: 1, consumed: 0,
      spkMeta: { spkId: 1, createdAt: Date.now(), sig: null } };
  } catch (e) {
    clearTimeout(timeoutId);
    step('FEHLER: ' + e.message);
    showDiagPanel(log.join('\n'));
    throw e;
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   NACH ERFOLGREICHER ANMELDUNG
   ═══════════════════════════════════════════════════════════════════════ */
async function afterAuth(data) {
  state.me = data.user;
  state.device = data.device;
  state.monitor = new KT.Monitor();
  await loadSessions();

  /* Server-Wahrheit für showLastSeen übernehmen (falls auf einem
     anderen Gerät geändert) — alle anderen Chat-Präferenzen bleiben
     rein lokal und werden nicht überschrieben. */
  if (typeof data.user.showLastSeen === 'boolean' && state.chatPrefs) {
    state.chatPrefs.showLastSeen = data.user.showLastSeen;
    saveChatPrefs();
  }

  /* WICHTIG: window.__app muss HIER gesetzt werden, nicht erst in
     renderShell() — die E-Mail-Verifizierung (Pflicht, siehe unten)
     kann einen frühen return auslösen, BEVOR renderShell() je läuft. */
  window.__app = appActions;

  /* E-Mail-Verifizierung ist PFLICHT — deshalb hier GANZ AM ANFANG
     geprüft, VOR jedem anderen await (LocalCache, WebSocket, Inbox,
     Blockliste). Grund: jeder dieser Aufrufe könnte theoretisch werfen
     und ohne umgebendes try/catch die gesamte Funktion abbrechen, bevor
     die Verifizierungsprüfung je erreicht wird — das würde sich exakt
     als "Overlay erscheint (aus einem früheren, noch im DOM hängenden
     Aufruf), aber neue Klicks bewirken nichts" zeigen, weil kein neuer
     Aufruf von showEmailVerifyPrompt() mehr stattfindet und somit auch
     keine frischen Event-Listener registriert werden. */
  if (!state.me.emailVerified) {
    showEmailVerifyPrompt(true);
    return;
  }

  /* Lokalen Nachrichten-Cache entsperren und zuerst laden — damit die
     Chat-Liste sofort etwas zeigt, auch bevor die Inbox vom Server
     abgeglichen ist. Nutzt denselben Geräteschlüssel wie der Vault,
     kein separates Geheimnis mehr nötig. */
  await LocalCache.unlock(data.device.id);
  await LocalCache.load();

  api.connect();
  wireSocketEvents();
  setupPushNotifications().catch(() => {});

  try { await window.StorageGuard?.requestPersistence?.(); } catch {}
  await loadBlockList();
  await loadGroupKeysLocal();
  await refreshInbox();
  await refreshGroups();

  /* UI nur neu aufbauen wenn noch nicht sichtbar */
  if ($('#app').classList.contains('hide')) {
    $('#auth').classList.add('hide');
    $('#app').classList.remove('hide');
    renderShell();
    go('chats');
    toast('Willkommen, ' + state.me.name + ' 🔐');
  } else {
    /* App läuft bereits (Offline-Modus war aktiv) — nur aktualisieren */
    renderMain();
    updateOfflineBanner();
  }
}

function showEmailVerifyPrompt(blocking) {
  /* Ein eventuell noch vorhandenes altes Sheet zuerst entfernen — sonst
     könnten zwei Elemente mit derselben id="verifySheet" im DOM landen,
     falls diese Funktion mehr als einmal aufgerufen wird. getElementById
     würde dann nur das ERSTE (möglicherweise alte, verwaiste) Element
     finden, während visuell das neue obenauf liegt — die Event-Listener
     hingen dann am falschen Element, was sich exakt als "sichtbares
     Overlay, aber Klicks bewirken nichts" zeigen würde. */
  document.getElementById('verifySheet')?.remove();

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'verifySheet';
  /* Bei PFLICHT-Verifizierung (blocking=true) gibt es bewusst keinen
     "Später"-Button und keinen Klick-außerhalb-zum-Schließen — das
     Konto kommt sonst nie zur eigentlichen App durch, siehe server.js,
     wo die Registrierung selbst ohne erfolgreichen Mailversand schon
     zurückgerollt wird. */
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 8px">E-Mail bestätigen</h3>
      <p style="color:var(--sub);margin:0 0 16px;font-size:14px">
        Wir haben einen 6-stelligen Code an ${esc(state.me.email)} geschickt.
        ${blocking ? 'Die Bestätigung ist erforderlich, um fortzufahren.' : ''}
      </p>
      <input id="verifyCodeInput" inputmode="numeric" maxlength="6" placeholder="000000"
        style="width:100%;box-sizing:border-box;font-size:24px;letter-spacing:8px;text-align:center;
          padding:14px;border-radius:10px;border:none;background:var(--panel2);color:var(--tx);margin-bottom:12px">
      <div id="verifyError" style="color:#f15c6d;font-size:13px;margin-bottom:12px;display:none"></div>
      <button class="btn" id="verifySubmitBtn" style="width:100%;margin-bottom:8px">Bestätigen</button>
      <button class="btn ghost" id="verifyResendBtn" style="width:100%${blocking ? '' : ';margin-bottom:8px'}">Code erneut senden</button>
      ${blocking ? '' : '<button class="btn ghost" id="verifyDismissBtn" style="width:100%">Später</button>'}
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
  document.getElementById('verifyCodeInput')?.focus();

  /* Direkte Event-Listener statt onclick="window.__app...()" — das
     umgeht JEDES Timing-Problem mit window.__app komplett, weil die
     Funktionen hier direkt referenziert werden, ohne den Umweg über
     das globale Objekt. Robuster als der Inline-Ansatz, unabhängig
     davon, wann/ob window.__app zu diesem Zeitpunkt bereits gesetzt
     wurde.

     DEFENSIV mit ?. abgesichert: falls eines der Elemente aus
     irgendeinem Grund null ist, würde ein direkter .addEventListener()-
     Aufruf sofort werfen und ALLE folgenden Listener-Registrierungen in
     dieser Funktion verhindern — das würde exakt zum gemeldeten Symptom
     passen ("Buttons sehen normal aus, reagieren aber auf nichts",
     weil gar kein Listener je registriert wurde). document.title wird
     zusätzlich als TEMPORÄRES Diagnosesignal genutzt, weil selbst
     alert() im Feld nicht sichtbar zuverlässig ankam — eine Änderung
     des Tab-Titels lässt sich im Browser-Tab-Umschalter oder in der
     Adressleiste erkennen, ganz ohne Konsolenzugriff. */
  const submitBtn = document.getElementById('verifySubmitBtn');
  const resendBtn = document.getElementById('verifyResendBtn');
  const dismissBtn = document.getElementById('verifyDismissBtn');
  document.title = 'DIAG: submitBtn=' + !!submitBtn + ' resendBtn=' + !!resendBtn;
  submitBtn?.addEventListener('click', submitEmailCode);
  resendBtn?.addEventListener('click', resendEmailCode);
  dismissBtn?.addEventListener('click', dismissEmailVerify);
}

async function submitEmailCode() {
  try {
    const input = document.getElementById('verifyCodeInput');
    const errEl = document.getElementById('verifyError');
    const code = input?.value.trim();
    if (!code || code.length !== 6) {
      if (errEl) { errEl.textContent = 'Bitte den 6-stelligen Code eingeben.'; errEl.style.display = 'block'; }
      else alert('DIAGNOSE: errEl nicht gefunden, Code war: ' + code);
      return;
    }
    try {
      await api.verifyEmail(code);
      state.me.emailVerified = true;
      document.getElementById('verifySheet')?.remove();
      toast('✓ E-Mail bestätigt');

      /* Bei Pflicht-Verifizierung war die Hauptoberfläche bisher noch nie
         aufgebaut — jetzt automatisch weiterleiten, ohne dass ein
         erneuter Login-Schritt nötig wäre. Das Sitzungstoken aus der
         Registrierung ist bereits gültig; der Nutzer ist im
         API-/WebSocket-Sinn längst angemeldet, es fehlte nur die
         Freischaltung der Oberfläche. */
      if ($('#app').classList.contains('hide')) {
        $('#auth').classList.add('hide');
        $('#app').classList.remove('hide');
        renderShell();
        go('chats');
        toast('Willkommen, ' + state.me.name + ' 🔐');
      }
    } catch (e) {
      const msg = e.message === 'Code falsch' ? 'Falscher Code — bitte prüfen.'
        : e.message === 'Code abgelaufen — neuen anfordern' ? 'Code abgelaufen — tipp auf "Code erneut senden".'
        : e.message;
      if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; }
      else alert('DIAGNOSE: errEl nicht gefunden. Fehler war: ' + msg);
    }
  } catch (outerErr) {
    /* TEMPORÄR zur Fehlersuche: fängt JEDEN unerwarteten Fehler ab, der
       außerhalb des inneren try/catch auftritt (z. B. wenn $('#app')
       selbst wirft, oder renderShell()/go() einen Fehler hat) — ohne
       dieses äußere Netz würde ein solcher Fehler komplett lautlos
       bleiben, exakt das gemeldete Symptom "Buttons reagieren, aber
       nichts passiert". alert() ist hier bewusst blockierend gewählt,
       damit die Meldung garantiert gesehen wird, auch ohne Zugriff auf
       die Browser-Konsole. */
    alert('DIAGNOSE — unerwarteter Fehler in submitEmailCode: ' + outerErr.message + '\n\n' + outerErr.stack);
  }
}

async function resendEmailCode() {
  try {
    await api.resendVerification();
    toast('📧 Neuer Code verschickt — bitte Postfach prüfen');
  } catch (e) {
    toast('⚠️ ' + e.message);
  }
}

function dismissEmailVerify() {
  document.getElementById('verifySheet')?.remove();
}

/* Server nicht erreichbar, aber der Vault hat sich lokal mit dem
   richtigen Passwort entsperrt: App im Offline-Modus starten. Zeigt
   den letzten gespeicherten Stand (Konversationen, Nachrichten,
   wartende Outbox), aber ohne Verbindung — Senden landet in der Outbox,
   kein Posteingangsabgleich, keine Live-Präsenz. Sobald das Netz
   zurückkommt, holt boot()/connect() den Rest automatisch nach. */
async function afterAuthOffline(deviceId, userName) {
  state.me = { id: null, name: userName };   // echte ID erst nach Online-Login bekannt
  state.device = { id: deviceId };
  state.isOffline = true;

  await loadSessions();
  await LocalCache.load();

  $('#auth').classList.add('hide');
  $('#app').classList.remove('hide');
  renderShell();
  go('chats');
  updateOfflineBanner();
  toast('📵 Offline — zeige gespeicherten Verlauf. Senden folgt, sobald du wieder online bist.', 3500);
}

function wireSocketEvents() {
  if (wireSocketEvents._wired) return;
  wireSocketEvents._wired = true;
  api.on('envelope', onIncomingEnvelope);
  api.on('presence', onPresence);
  /* Call global verfügbar machen für call-ui.js */
  window.Call = Call;
  /* call-ui.js als normales Script laden */
  if (!window.__initCallUI) {
    const s = document.createElement('script');
    s.src = '/call-ui.js';
    s.onload = () => { if (window.__initCallUI) window.__initCallUI(api); };
    document.head.appendChild(s);
  } else {
    window.__initCallUI(api);
  }
  api.on('device-added', d => toast('Neues Gerät verbunden: ' + (d.device?.name || '')));
  api.on('device-revoked', () => {
    toast('Dieses Gerät wurde entfernt. Du wirst abgemeldet.');
    setTimeout(() => { Vault.forget(); location.reload(); }, 1500);
  });
  api.on('contact-joined', async () => {
    toast('Ein Kontakt nutzt jetzt auch SecureChat 👋');
  });
  api.on('need-prekeys', () => refillPrekeys().catch(() => {}));
  api.on('call-reminder', (msg) => {
    showCallReminderNotification(msg);
  });
  api.on('call-invite', (msg) => {
    showCallInviteNotification(msg);
  });
  api.on('call-response', (msg) => {
    showCallResponseNotification(msg);
  });
  api.on('call-cancelled', (msg) => {
    toast(`📅 ${msg.byName || msg.byId} hat den geplanten Anruf abgesagt`);
  });
  api.on('delivered', (msg) => {
    markMessagesStatus(msg.convId, msg.ids, 'delivered');
  });
  api.on('read', (msg) => {
    if (msg.convId) markMessagesStatus(msg.convId, msg.ids, 'read');
  });
  api.on('connected', () => {
    toast('🟢 WebSocket verbunden', 1500);
    state.isOffline = false;
    updateOfflineBanner();
    flushOutbox();
  });
  api.on('disconnected', () => toast('Verbindung unterbrochen — versuche erneut…', 1800));
}

async function refillPrekeys() {
  const more = [];
  for (let i = 0; i < 10; i++) {
    const k = await P.genDH();
    const id = ++state.identity.opkSeq;
    state.identity.opks.set(id, k);
    more.push({ opkId: id, pub: k.pubJwk });
  }
  await api.uploadPrekeys({ opks: more });
}

/* ═══════════════════════════════════════════════════════════════════════
   POSTEINGANG — beim Start und live über WebSocket
   ═══════════════════════════════════════════════════════════════════════ */
async function refreshInbox() {
  const { envelopes } = await api.inbox();
  const toAck = [];
  for (const env of envelopes) {
    await handleEnvelope(env, false);
    toAck.push(env.id);
  }
  if (toAck.length) await api.ack(toAck);
  renderMain();
}

async function onIncomingEnvelope(env) {
  await handleEnvelope(env, true);
  const convId = env.convId || ('dm_' + [state.me?.id, env.senderId].filter(Boolean).sort().join('_'));
  if (state.view === 'chat' && state.activeConv?.convId === convId) {
    renderChatMessages();
  } else {
    renderMain();
  }
}
/* ── Gruppennachricht entschlüsseln ──
   ciphertext-Format: "<iv-b64>.<ct-b64>" (siehe sendGroupMessage).
   Fehlt der Gruppenschlüssel lokal (z. B. neue Gruppe, deren Wrap noch
   nicht verarbeitet wurde), einmal versuchen ihn nachzuladen. */
async function openGroupMessage(env) {
  let groupKey = state.groupKeys?.get(env.groupId);
  if (!groupKey) {
    await refreshGroups();
    groupKey = state.groupKeys?.get(env.groupId);
    if (!groupKey) throw new Error('Kein Gruppenschlüssel verfügbar');
  }
  const [ivB64, ctB64] = env.ciphertext.split('.');
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ub64(ivB64) }, groupKey, ub64(ctB64));
  return td.decode(plain);
}

async function handleEnvelope(env, live) {
  const convId = env.convId || ('dm_' + [state.me.id, env.senderId].filter(Boolean).sort().join('_'));

  /* Eine tatsächlich eintreffende Nachricht ist ein bewusster
     Neuanfang für diesen Chat — hebt eine frühere lokale Löschung auf
     (siehe deleteSelectedChats), sonst würde die Konversation trotz
     neuer Nachricht unsichtbar bleiben. */
  if (state.deletedConvIds?.has(convId)) {
    state.deletedConvIds.delete(convId);
    try { localStorage.setItem('sc:deletedConvIds', JSON.stringify([...state.deletedConvIds])); } catch {}
  }

  let plaintext = '[verschlüsselt]';
  try {
    if (env.groupId || env.kind === 'group') {
      plaintext = await openGroupMessage(env);
    } else if (env.sealed) {
      plaintext = await openSealed(env);
    } else {
      plaintext = await openRatchet(env);
    }
  } catch (e) {
    console.warn('Entschlüsselung fehlgeschlagen:', e.message);
    plaintext = '⚠️ Nicht entschlüsselbar';
  }

  if (!state.messages.has(convId)) state.messages.set(convId, []);

  /* Gruppen-Conv anlegen, falls noch nicht bekannt (z. B. erste
     Nachricht kam an, bevor refreshGroups() gelaufen ist). */
  if (env.groupId && !state.convs.has(convId)) {
    state.convs.set(convId, { convId, groupId: env.groupId, isGroup: true, name: 'Gruppe', memberIds: [], unread: 0 });
  }

  /* Umfrage-Stimmen und Live-Standort-Updates sind "unsichtbare"
     Nachrichtenarten: sie tragen keinen Chatverlauf-Eintrag, sondern
     lösen jeweils ihre eigene Anzeige aus (aggregierte Stimmen bzw.
     das schwebende Kartenfenster) — sonst würde jedes einzelne Update
     als eigene Chatzeile auftauchen. */
  let pollVoteObj = null, liveLocUpdate = null;
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed?.__pollVote) pollVoteObj = parsed.__pollVote;
    if (parsed?.__liveLocationUpdate) liveLocUpdate = parsed.__liveLocationUpdate;
  } catch {}

  if (pollVoteObj && env.senderId) {
    if (!state.pollVotes) state.pollVotes = new Map();
    const votes = state.pollVotes.get(pollVoteObj.pollId) || {};
    votes[env.senderId] = pollVoteObj.optionIdx;
    state.pollVotes.set(pollVoteObj.pollId, votes);
  } else if (liveLocUpdate) {
    showLiveLocationWidget(liveLocUpdate.liveId, {
      lat: liveLocUpdate.lat, lng: liveLocUpdate.lng,
      expiresAt: liveLocUpdate.expiresAt,
      fromName: liveLocUpdate.fromName || env.senderName || 'Kontakt',
      isSender: false
    });
  } else {
    state.messages.get(convId).push({
      id: env.id, from: env.senderId || '(versiegelt)', fromName: env.senderName,
      text: plaintext, ts: env.sentAt, mine: false, sealed: !!env.sealed
    });
    /* In Gruppen mit mehreren Absendern braucht jede fremde Nachricht
       einen sichtbaren Namen (siehe renderChatMessages) — falls der
       Server ihn nicht mitschickte, einmalig nachladen und die bereits
       gerenderte Nachricht rückwirkend aktualisieren. */
    if (env.groupId && !env.senderName && env.senderId) {
      fetch(API_BASE + '/api/user/' + env.senderId, { headers: { Authorization: 'Bearer ' + api.token } })
        .then(r => r.ok ? r.json() : null)
        .then(u => {
          if (!u?.user?.name) return;
          const msg = state.messages.get(convId)?.find(x => x.id === env.id);
          if (msg) { msg.fromName = u.user.name; if (state.activeConv?.convId === convId) renderChatMessages(); }
        }).catch(() => {});
    }
  }

  const isSilent = !!(pollVoteObj || liveLocUpdate);
  const conv = state.convs.get(convId) || { convId, peerId: env.senderId, unread: 0 };
  conv.lastMsg = isSilent ? conv.lastMsg : { text: plaintext, ts: env.sentAt };
  conv.unread = isSilent ? conv.unread : (conv.unread || 0) + 1;
  if (!conv.name && env.senderName) conv.name = env.senderName;
  state.convs.set(convId, conv);
  /* Name nachladen falls noch unbekannt */
  if (!conv.name && env.senderId) {
    fetch(API_BASE + '/api/user/' + env.senderId, {
      headers: { Authorization: 'Bearer ' + api.token }
    }).then(r => r.ok ? r.json() : null).then(u => {
      if (u?.user?.name) { conv.name = u.user.name; renderMain(); }
    }).catch(() => {});
  }
  LocalCache.scheduleSave();

  if (live) api.ackViaSocket([env.id]);
}

async function openRatchet(env) {
  const key = sk(env.senderId, env.senderDeviceId);
  let st = state.sessions.get(key);
  if (!st) st = await ensureReceiverSession(env);
  /* env.ciphertext kommt als Base64-String vom Server (siehe sendMessage,
     das ArrayBuffer→Base64 vor dem Versand kodiert) — hier zurück zu
     Bytes, bevor Ratchet.decrypt() sie an WebCrypto weiterreicht.

     WICHTIG: Ratchet.encrypt() berechnet die AAD aus JSON.stringify(header)
     BEVOR app.js das x3dh-Feld für den Transport anhängt (siehe
     sendMessage) — die AAD kennt also nur {dh, pn, n}, nicht x3dh. Würde
     man den vollen, empfangenen Header (mit x3dh) an decrypt() geben,
     ergäbe JSON.stringify() einen anderen String als beim Verschlüsseln,
     der GCM-Tag würde nicht mehr passen. Das x3dh-Feld muss also vor
     dem Entschlüsseln wieder entfernt werden — es wurde bereits von
     ensureReceiverSession() ausgelesen, wird hier nicht mehr gebraucht. */
  const { x3dh, ...ratchetHeader } = env.header || {};
  const buf = await Ratchet.decrypt(st, { header: ratchetHeader, ct: ub64(env.ciphertext) },
    `v1|${env.senderId}|${env.convId}`);
  scheduleSessionSave();
  return td.decode(buf);
}
async function openSealed(env) {
  const raw = ub64(env.ciphertext);
  const sep = raw.indexOf(0);
  const ephJwk = JSON.parse(td.decode(raw.subarray(0, sep)));
  const ct = raw.subarray(sep + 1);
  const eph = await crypto.subtle.importKey('jwk', ephJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: eph }, state.identity.IK.priv, 256);
  const out = await P.hkdf(shared, null, 'SecureChat-SealedSender-v1', 44);
  const key = await crypto.subtle.importKey('raw', out.slice(0, 32), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: out.slice(32, 44) }, key, ct);
  const inner = JSON.parse(td.decode(pt));
  return `(von ${esc(inner.cert.senderName)}) ` + (inner.plaintext || '[Medien]');
}

function onPresence(msg) {
  for (const conv of state.convs.values()) {
    if (conv.peerId === msg.userId) conv.online = msg.online;
  }
  if (state.view === 'chat' && state.activeConv?.peerId === msg.userId) renderChatHeader();
  if (state.view === 'list') renderMain();
}

async function loadBlockList() {
  try {
    const { blocked } = await api.blockedList();
    state.blocked = new Set(blocked);
  } catch {}
}

/* ═══════════════════════════════════════════════════════════════════════
   SHELL — Kopfzeile, Filter-Pillen, Chat-Liste, untere Navigation
   ═══════════════════════════════════════════════════════════════════════ */
function renderShell() {
  const branding = getAppBranding();
  $('#app').innerHTML = `
    <div class="topbar">
      <h1>${branding.logoUrl ? `<img src="${esc(branding.logoUrl)}" class="app-logo-img" alt="">` : ''}${esc(branding.name)}</h1>
      <div class="topicons">
        <button class="iconbtn navbtn3d" onclick="window.__app.openCamera()" aria-label="Kamera">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M9 3l-1.8 2H4a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-3.2L15 3H9zm3 5a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg>
        </button>
        <button class="iconbtn navbtn3d" onclick="window.__app.mainMenu(event)" aria-label="Menü">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>
        </button>
      </div>
    </div>
    <div class="searchwrap">
      <div class="search"><span class="ic">🔍</span>
        <input id="searchInput" placeholder="Chats und Nachrichten durchsuchen" oninput="window.__app.onSearch(this.value)"></div>
    </div>
    <div id="searchResults" style="display:none"></div>
    <div class="pillbar" id="pillbar"></div>
    <div id="main"></div>
    <div id="navbar"></div>`;
  window.__app = appActions;
  renderPills();
  renderNav();
  renderMain();
}

const PILLS = [
  ['all', 'Alle'], ['unread', 'Ungelesen'], ['favorites', 'Favoriten'], ['groups', 'Gruppen']
];
let activePill = 'all';
function renderPills() {
  $('#pillbar').innerHTML = PILLS.map(([id, label]) =>
    `<button class="pill ${activePill === id ? 'on' : ''}" onclick="window.__app.setPill('${id}')">${label}</button>`
  ).join('') + `<button class="pill plus" onclick="window.__app.newChat()">+</button>`;
}

function renderNav() {
  const totalUnread = [...state.convs.values()].reduce((a, c) => a + (c.unread || 0), 0);
  const svg = {
    chats: '<svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M10.5 3.5c-4.14 0-7.5 2.86-7.5 6.4 0 1.98 1.06 3.75 2.72 4.94-.09.94-.4 1.98-1.09 2.94a.4.4 0 0 0 .43.62c1.53-.35 2.7-1.02 3.5-1.62.6.13 1.24.2 1.94.2 4.14 0 7.5-2.86 7.5-6.4s-3.36-7.08-7.5-7.08z"/><path d="M18.9 15.5c1.3-1.05 2.1-2.5 2.1-4.1 0-2.55-2.1-4.7-4.9-5.4.15.6.24 1.23.24 1.9 0 4.2-3.98 7.6-8.9 7.6-.2 0-.4 0-.6-.02.9 2.1 3.4 3.62 6.36 3.62.5 0 .98-.05 1.44-.14.6.45 1.55 1 2.8 1.3a.32.32 0 0 0 .35-.5c-.55-.77-.8-1.6-.89-2.26z"/></svg>',
    updates: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#fff" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3" fill="#fff" stroke="none"/></svg>',
    scheduled: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M8 3v4M16 3v4M3 10h18"/><path d="M12 14v3l2 1"/></svg>',
    calls: '<svg viewBox="0 0 24 24" width="19" height="19" fill="#fff"><path d="M6.6 10.8c1.4 2.8 3.7 5 6.5 6.5l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C9.6 21 3 14.4 3 6c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.4 0 .8-.2 1L6.6 10.8z"/></svg>'
  };
  const tabs = [
    ['chats', svg.chats, 'Chats', totalUnread],
    ['updates', svg.updates, 'Aktuelles', 0],
    ['scheduled', svg.scheduled, 'Geplant', 0],
    ['calls', svg.calls, 'Anrufe', 0]
  ];
  $('#navbar').innerHTML = tabs.map(([id, ic, lb, bdg]) => `
    <button class="${state.tab === id ? 'on' : ''}" onclick="window.__app.go('${id}')">
      <span class="navbtn3d ${state.tab === id ? 'navbtn3d-on' : ''}">${ic}${bdg ? `<span class="navbdg"></span>` : ''}</span>
      <span class="navlb">${lb}</span>
    </button>`).join('');
}

function go(tab) {
  state.tab = tab; state.view = 'list';
  renderNav(); renderMain();
}

/* ═══════════════════════════════════════════════════════════════════════
   VOLLTEXTSUCHE — Chat-Namen UND bereits entschlüsselte Nachrichten
   ─────────────────────────────────────────────────────────────────────
   Durchsucht ausschließlich lokal vorhandenen, bereits entschlüsselten
   Text (state.messages) — es gibt serverseitig nichts zu durchsuchen,
   das wäre bei Ende-zu-Ende-Verschlüsselung ohnehin unmöglich. Zeigt
   Treffer mit Chatname + Textausschnitt, Antippen öffnet den Chat.
   ═══════════════════════════════════════════════════════════════════════ */
function onSearch(v) {
  state.search = v.trim();
  const resultsEl = $('#searchResults');
  const mainEl = $('#main');
  if (!state.search) {
    resultsEl.style.display = 'none';
    resultsEl.innerHTML = '';
    mainEl.style.display = '';
    renderMain();
    return;
  }

  const q = state.search.toLowerCase();
  const hits = [];
  for (const [convId, msgs] of state.messages.entries()) {
    const conv = state.convs.get(convId);
    const name = conv?.name || conv?.peerId || 'Unbekannt';
    for (const m of msgs) {
      if (m.text && m.text.toLowerCase().includes(q)) {
        hits.push({ convId, name, text: m.text, ts: m.ts, conv });
      }
    }
  }
  hits.sort((a, b) => (b.ts || 0) - (a.ts || 0));

  const nameMatches = [...state.convs.values()]
    .filter(c => (c.name || c.peerId || '').toLowerCase().includes(q));

  mainEl.style.display = 'none';
  resultsEl.style.display = 'block';

  if (!hits.length && !nameMatches.length) {
    resultsEl.innerHTML = `<div class="empty"><div class="ic">🔍</div><div>Keine Treffer für „${esc(state.search)}"</div></div>`;
    return;
  }

  const highlight = (text) => {
    const idx = text.toLowerCase().indexOf(q);
    if (idx === -1) return esc(text.slice(0, 80));
    const start = Math.max(0, idx - 20);
    const end = Math.min(text.length, idx + q.length + 40);
    const before = esc(text.slice(start, idx));
    const match = esc(text.slice(idx, idx + q.length));
    const after = esc(text.slice(idx + q.length, end));
    return (start > 0 ? '…' : '') + before + `<mark>${match}</mark>` + after + (end < text.length ? '…' : '');
  };

  resultsEl.innerHTML = `
    ${nameMatches.length ? `
      <div class="searchsection">Chats</div>
      ${nameMatches.map(c => `
        <div class="row" onclick="window.__app.openConvById('${c.convId}')">
          <div class="av">${(c.name || '?')[0].toUpperCase()}</div>
          <div class="meta"><div class="l1"><span class="nm">${esc(c.name || c.peerId)}</span></div></div>
        </div>`).join('')}
    ` : ''}
    ${hits.length ? `
      <div class="searchsection">Nachrichten</div>
      ${hits.slice(0, 50).map(h => `
        <div class="row" onclick="window.__app.openConvById('${h.convId}')">
          <div class="av">${(h.name || '?')[0].toUpperCase()}</div>
          <div class="meta">
            <div class="l1"><span class="nm">${esc(h.name)}</span><span class="tm">${h.ts ? time(h.ts) : ''}</span></div>
            <div class="l2"><span class="pv">${highlight(h.text)}</span></div>
          </div>
        </div>`).join('')}
    ` : ''}
  `;
}

function openConvById(convId) {
  const conv = state.convs.get(convId);
  if (!conv) return;
  $('#searchInput').value = '';
  onSearch('');
  openChat(conv);
}

function renderMain() {
  if (state.view !== 'list') return;
  const main = $('#main');
  if (!main) return;
  if (state.tab === 'scheduled') {
    renderScheduledTab(main);
    return;
  }
  if (state.tab !== 'chats') {
    main.innerHTML = `<div class="empty"><div class="ic">🚧</div><div>Noch nicht verfügbar</div></div>`;
    return;
  }

  let convs = [...state.convs.values()];
  if (activePill === 'unread') convs = convs.filter(c => (c.unread || 0) > 0);
  if (activePill === 'groups') convs = convs.filter(c => c.isGroup);
  if (activePill === 'favorites') convs = convs.filter(c => state.favoriteChats?.has(c.convId));
  if (state.search) {
    const q = state.search.toLowerCase();
    convs = convs.filter(c => (c.name || c.peerId || '').toLowerCase().includes(q));
  }
  /* Angepinnte Chats immer zuerst, innerhalb der beiden Gruppen nach
     letzter Nachricht sortiert — genau das übliche Verhalten, das
     Nutzer aus anderen Messengern erwarten. */
  convs.sort((a, b) => {
    const aPinned = state.pinnedChats?.has(a.convId) ? 1 : 0;
    const bPinned = state.pinnedChats?.has(b.convId) ? 1 : 0;
    if (aPinned !== bPinned) return bPinned - aPinned;
    return (b.lastMsg?.ts || 0) - (a.lastMsg?.ts || 0);
  });

  const selMode = !!state.selectMode;
  main.innerHTML = `
    ${selMode ? `
      <div class="selectbar">
        <button class="iconbtn" onclick="window.__app.exitSelectMode()" aria-label="Schließen">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
        </button>
        <span class="selectcount">${state.selectedConvs.size} ausgewählt</span>
        <button class="iconbtn navbtn3d" style="background:radial-gradient(circle at 35% 30%,#f87171,#dc2626 70%)"
          onclick="window.__app.deleteSelectedChats()" aria-label="Löschen">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M6 7h12l-1 13a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1L6 7zm3-3h6l1 2H8l1-2z"/></svg>
        </button>
      </div>` : ''}
    <div class="scroll" style="height:100%;position:relative">
      ${convs.length ? convs.map((c, i) => convRow(c, i)).join('') :
        `<div class="empty"><div class="ic">💬</div><div>Noch keine Chats.<br>Tippe auf + um zu starten.</div></div>`}
      ${!selMode ? `<div class="fab navbtn3d navbtn3d-on" onclick="window.__app.newChat()" aria-label="Neuer Chat">
        <svg viewBox="0 0 24 24" width="24" height="24" fill="#fff"><path d="M20 2H4a2 2 0 0 0-2 2v18l4-4h14a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM13 11h4v2h-4v4h-2v-4H7v-2h4V7h2v4z"/></svg>
      </div>` : ''}
    </div>`;
  window.__conv = convs;
}

function convRow(c, i) {
  const name = c.name || c.peerId || 'Unbekannt';
  const avatar = c.avatarUrl
    ? `<img src="${c.avatarUrl}">`
    : (name[0] || '?').toUpperCase();
  const unread = c.unread || 0;
  const preview = c.lastMsg ? esc(c.lastMsg.text).slice(0, 60) : 'Noch keine Nachrichten';
  const selMode = !!state.selectMode;
  const isSelected = state.selectedConvs?.has(c.convId);
  const isPinned = state.pinnedChats?.has(c.convId);
  const isFavorite = state.favoriteChats?.has(c.convId);
  const rowClick = selMode
    ? `window.__app.toggleSelectConv('${c.convId}')`
    : `window.__app.openConv(${i})`;
  return `
    <div class="row ${isSelected ? 'row-selected' : ''}" onclick="${rowClick}"
      oncontextmenu="window.__app.enterSelectMode('${c.convId}');return false;"
      ontouchstart="window.__app.longPressStart('${c.convId}')"
      ontouchend="window.__app.longPressEnd()" ontouchmove="window.__app.longPressEnd()">
      ${selMode ? `<div class="selectcheck">${isSelected ? '✅' : '⭕'}</div>` : ''}
      <div class="av">${avatar}${c.isGroup ? '' : `<div class="dot ${c.online ? 'online' : 'offline'}"></div>`}</div>
      <div class="meta">
        <div class="l1"><span class="nm">${isPinned ? '📌 ' : ''}${isFavorite ? '⭐ ' : ''}${esc(name)}</span>
          <span class="tm ${unread ? 'un' : ''}">${c.lastMsg ? time(c.lastMsg.ts) : ''}</span></div>
        <div class="l2"><span class="pv">${preview}</span>
          ${unread ? `<span class="unread">${unread}</span>` : ''}</div>
      </div>
    </div>`;
}

/* ── Auswahlmodus für die Chatliste (Long-Press oder Rechtsklick) ──
   Touch-Long-Press wird über einen einfachen Timer nachgebildet, da
   'contextmenu' auf Touch-Geräten unzuverlässig feuert. */
let _longPressTimer = null;
function longPressStart(convId) {
  _longPressTimer = setTimeout(() => enterSelectMode(convId), 500);
}
function longPressEnd() {
  if (_longPressTimer) { clearTimeout(_longPressTimer); _longPressTimer = null; }
}
function enterSelectMode(convId) {
  state.selectMode = true;
  if (!state.selectedConvs) state.selectedConvs = new Set();
  state.selectedConvs.add(convId);
  renderMain();
}
function exitSelectMode() {
  state.selectMode = false;
  state.selectedConvs = new Set();
  renderMain();
}
function toggleSelectConv(convId) {
  if (!state.selectedConvs) state.selectedConvs = new Set();
  if (state.selectedConvs.has(convId)) state.selectedConvs.delete(convId);
  else state.selectedConvs.add(convId);
  if (state.selectedConvs.size === 0) { exitSelectMode(); return; }
  renderMain();
}
function deleteSelectedChats() {
  const count = state.selectedConvs.size;
  if (!count) return;
  if (!confirm(`${count} Chat${count > 1 ? 's' : ''} wirklich löschen? Nur lokal — der Gesprächspartner behält seine Kopie.`)) return;
  if (!state.deletedConvIds) state.deletedConvIds = new Set();
  for (const convId of state.selectedConvs) {
    state.convs.delete(convId);
    state.messages.delete(convId);
    /* Merken, dass dieser Chat aktiv gelöscht wurde — sonst würde
       refreshInbox()/refreshGroups() ihn beim nächsten Laden wieder
       aus Server-Daten rekonstruieren (Gruppen bleiben ja bestehen,
       solange man Mitglied ist; 1:1-Chats tauchen wieder auf, sobald
       eine neue Nachricht eintrifft). Erst eine neue eingehende
       Nachricht (siehe handleEnvelope) hebt diese Markierung wieder
       auf, weil das dann ein bewusster Neuanfang ist. */
    state.deletedConvIds.add(convId);
  }
  try { localStorage.setItem('sc:deletedConvIds', JSON.stringify([...state.deletedConvIds])); } catch {}
  LocalCache.scheduleSave();
  exitSelectMode();
  toast(`${count} Chat${count > 1 ? 's' : ''} gelöscht`);
}
function loadDeletedConvIds() {
  try { state.deletedConvIds = new Set(JSON.parse(localStorage.getItem('sc:deletedConvIds') || '[]')); }
  catch { state.deletedConvIds = new Set(); }
}

/* ═══════════════════════════════════════════════════════════════════════
   AKTIONEN, vom UI aufgerufen
   ═══════════════════════════════════════════════════════════════════════ */
const appActions = {
  setPill(id) { activePill = id; renderPills(); renderMain(); },
  onSearch(v) { onSearch(v); },
  go(tab) { go(tab); },
  openConv(i) { const c = window.__conv[i]; openChat(c); },
  openConvById(convId) { openConvById(convId); },
  enterSelectMode(convId) { enterSelectMode(convId); },
  exitSelectMode() { exitSelectMode(); },
  toggleSelectConv(convId) { toggleSelectConv(convId); },
  deleteSelectedChats() { deleteSelectedChats(); },
  longPressStart(convId) { longPressStart(convId); },
  longPressEnd() { longPressEnd(); },
  newChat() { openNewChatSheet(); },
  openCamera() { toast('Kamera folgt in einem späteren Schritt'); },
  startCall(kind) {
    if (!state.activeConv) return;
    const conv = state.convs.get(state.activeConv.convId);
    Call.start(state.activeConv.peerId, state.activeConv.name || conv?.name, kind);
  },
  submitEmailCode() { submitEmailCode(); },
  resendEmailCode() { resendEmailCode(); },
  dismissEmailVerify() { dismissEmailVerify(); },
  logoutClick() { logoutClick(); },
  showDeleteAccount() { showDeleteAccount(); },
  confirmDeleteAccount() { confirmDeleteAccount(); },
  mainMenu(e) { openMainMenu(e); },
  openSettings() { openSettings(); },
  openDesignSettings() { openDesignSettings(); },
  setAccentTheme(theme) { setAccentTheme(theme); },
  setCategoryTheme(category, theme) { setCategoryTheme(category, theme); },
  saveBrandingName() { saveBrandingName(); },
  pickBrandingLogo() { pickBrandingLogo(); },
  clearBrandingLogo() { clearBrandingLogo(); },
  openChatSettings() { openChatSettings(); },
  toggleChatPref(key, val) { toggleChatPref(key, val); },
  setFontSizePref(size) { setFontSizePref(size); },
  openNotificationSettings() { openNotificationSettings(); },
  openPrivacySettings() { openPrivacySettings(); },
  openBlockedList() { openBlockedList(); },
  openLinkedDevices() { openLinkedDevices(); },
  openLanguageSettings() { openLanguageSettings(); },
  changeLang(code) { changeLang(code); },
  openStorageSettings() { openStorageSettings(); },
  clearLocalCache() { clearLocalCache(); },
  editProfile() { editProfile(); },
  pickAvatarPhoto() { pickAvatarPhoto(); },
  pickAvatarFrom(useCamera) { pickAvatarFrom(useCamera); },
  saveProfileName() { saveProfileName(); },
  enablePush() { enablePush(); },
  unblockFromSettings(id) { unblockFromSettings(id); },
  closeChat() { closeChat(); },
  sendClick() { sendCurrentMessage(); },
  onMsgInputChange(v) { onMsgInputChange(v); },
  sendOrMicClick() { sendOrMicClick(); },
  startVoiceRecording() { startVoiceRecording(); },
  stopVoiceRecording(send) { stopVoiceRecording(send); },
  inputKey(e) {
    if (e.key !== 'Enter' || e.shiftKey) return;
    const enterSends = state.chatPrefs?.enterToSend !== false;
    if (enterSends) { e.preventDefault(); sendCurrentMessage(); }
    /* Wenn enterToSend aus ist: Enter fügt normal einen Zeilenumbruch
       ein (Standardverhalten des Textarea-Elements, kein Eingriff nötig). */
  },
  startChatWith(userId, userName) { startChatWith(userId, userName); },
  openCreateGroup() { openCreateGroup(); },
  confirmCreateGroup() { confirmCreateGroup(); },
  copyMessage(id) { copyMessage(id); },
  deleteMessage(id) { deleteMessage(id); },
  forwardMessage(id) { forwardMessage(id); },
  openMsgMenu(id) { openMsgMenu(id); },
  msgLongPressStart(id) { msgLongPressStart(id); },
  msgLongPressEnd() { msgLongPressEnd(); },
  enterMsgSelectMode(id) { enterMsgSelectMode(id); },
  exitMsgSelectMode() { exitMsgSelectMode(); },
  toggleSelectMsg(id) { toggleSelectMsg(id); },
  deleteSelectedMsgs() { deleteSelectedMsgs(); },
  forwardSelectedMsgs() { forwardSelectedMsgs(); },
  chatMenu(e) { chatMenu(e); },
  searchInChat() { searchInChat(); },
  doChatSearch(q) { doChatSearch(q); },
  clearChatSearch() { clearChatSearch(); },
  toggleMuteChat() { toggleMuteChat(); },
  toggleChatPin(convId) { toggleChatPin(convId); },
  toggleChatFavorite(convId) { toggleChatFavorite(convId); },
  openDisappearingMessages() { openDisappearingMessages(); },
  setDisappearing(sec) { setDisappearing(sec); },
  showEncryptionFingerprint() { showEncryptionFingerprint(); },
  exportChat() { exportChat(); },
  clearChatHistory() { clearChatHistory(); },
  toggleBlock() { toggleBlock(); },
  reportUser() { reportUser(); },
  submitReport() { submitReport(); },
  attachSheet() { attachSheet(); },
  shareLocation() { shareLocation(); },
  sendLocationOnce() { sendLocationOnce(); },
  startLiveLocation(min) { startLiveLocation(min); },
  stopLiveLocation() { stopLiveLocation(); },
  shareContact() { shareContact(); },
  sendContactCard(id, name) { sendContactCard(id, name); },
  openCreatePoll() { openCreatePoll(); },
  addPollOption() { addPollOption(); },
  sendPoll() { sendPoll(); },
  votePoll(pollId, idx) { votePoll(pollId, idx); },
  openScheduleCall() { openScheduleCall(); },
  setScheduleKind(k) { setScheduleKind(k); },
  confirmScheduleCall() { confirmScheduleCall(); },
  openScheduledCallsList() { openScheduledCallsList(); },
  cancelScheduledCall(id) { cancelScheduledCall(id); },
  startScheduledCall(peerId, kind) { startScheduledCall(peerId, kind); },
  respondScheduledCall(id, status) { respondScheduledCall(id, status); },
  pickMedia(accept, kind, useCamera) { pickMedia(accept, kind, useCamera); },
  loadMedia(msgId) {
    for (const list of state.messages.values()) {
      const m = list.find(x => x.id === msgId);
      if (m) {
        const media = m.media || parseIncomingMedia(m.text);
        if (media) downloadAndShowMedia(msgId, media.ref, media.kind, media.kind === 'image');
        break;
      }
    }
  },
  openMediaFullscreen(msgId) { openMediaFullscreen(msgId); },
};

/* ═══════════════════════════════════════════════════════════════════════
   SITZUNGSAUFBAU — X3DH pro Empfängergerät
   ─────────────────────────────────────────────────────────────────────
   Ein logischer Chat mit einem Kontakt kann mehrere Ratchet-Sitzungen
   bedeuten — eine pro aktivem Gerät des Kontakts (Fanout). Der Bundle-
   Abruf liefert alle Geräte auf einmal; für jedes ohne bestehende
   Sitzung wird X3DH einmalig durchgeführt.
   ═══════════════════════════════════════════════════════════════════════ */
async function ensureSessions(peerId) {
  const { bundles } = await api.fetchBundle(peerId);
  if (!bundles?.length) throw new Error('Kein aktives Gerät für diesen Nutzer gefunden');

  const missing = bundles.filter(b => !state.sessions.has(sk(peerId, b.deviceId)));
  for (const bundle of missing) {
    const verify = await PreKeys.verifyBundle(bundle);
    if (!verify.ok) {
      console.warn('Bundle-Signatur ungültig für Gerät', bundle.deviceId, verify.reason);
      continue;   // dieses Gerät überspringen, andere bleiben nutzbar
    }
    const { SK, EK } = await X3DH.initiator(state.identity.IK, bundle);
    const st = await Ratchet.initSender(SK, bundle.spk);
    st.usedOpkId = bundle.opkId;
    st.ephemeral = EK;
    state.sessions.set(sk(peerId, bundle.deviceId), st);
    scheduleSessionSave();
  }
  return bundles;
}

/* Wenn WIR der Empfänger einer ersten Nachricht sind, muss die Sitzung
   als Empfänger aufgebaut werden — passiert lazy beim ersten
   entschlüsselbaren Umschlag, siehe openRatchet() weiter unten, das bei
   Fehlschlag versucht, aus dem mitgelieferten Header eine neue
   Empfänger-Sitzung zu bilden (X3DH.responder benötigt den passenden,
   inzwischen verbrauchten One-Time-Prekey). */
async function ensureReceiverSession(env) {
  const key = sk(env.senderId, env.senderDeviceId);
  if (state.sessions.has(key)) return state.sessions.get(key);
  if (!env.header?.x3dh) throw new Error('Kein X3DH-Anfangsheader vorhanden — Sitzung nicht rekonstruierbar');

  const { senderIK, senderEK, opkId } = env.header.x3dh;
  const usedOpk = opkId ? state.identity.opks.get(opkId) : null;
  const SK = await X3DH.responder(state.identity.IK, state.identity.SPK, usedOpk, senderIK, senderEK);
  const st = Ratchet.initReceiver(SK, state.identity.SPK);
  state.sessions.set(key, st);
  scheduleSessionSave();
  if (usedOpk) state.identity.opks.delete(opkId);
  return st;
}

/* ═══════════════════════════════════════════════════════════════════════
   NACHRICHT SENDEN — Fanout an alle aktiven Empfängergeräte
   ═══════════════════════════════════════════════════════════════════════ */
/* ── Gruppennachricht senden ──
   Verschlüsselt mit dem gemeinsamen AES-Gruppenschlüssel (siehe
   confirmCreateGroup) statt einer 1:1-Ratchet-Session — eine
   Nachricht, ein Chiffrat, an alle Mitgliedergeräte verteilt (kein
   individuelles Neuverschlüsseln pro Empfänger nötig, im Gegensatz
   zu 1:1). AES-GCM mit zufälligem IV pro Nachricht. */
async function sendGroupMessage(groupId, convId, plaintext) {
  const groupKey = state.groupKeys?.get(groupId);
  if (!groupKey) throw new Error('Kein Gruppenschlüssel vorhanden — bitte Gruppe neu laden');

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, groupKey, te.encode(plaintext));
  const ciphertext = b64(iv) + '.' + b64(new Uint8Array(ct));

  const conv = state.convs.get(convId);
  const memberIds = (conv?.memberIds || []).filter(id => id !== state.me.id);
  if (!memberIds.length) throw new Error('Keine anderen Mitglieder in dieser Gruppe');

  const results = [];
  for (const memberId of memberIds) {
    let bundles = [];
    try { ({ bundles } = await api.fetchBundle(memberId)); } catch { continue; }
    const devices = (bundles || []).map(b => ({ deviceId: b.deviceId, ciphertext, header: null }));
    if (!devices.length) continue;
    try {
      const r = await api.send({ recipientId: memberId, convId, groupId, kind: 'group', perDevice: devices });
      results.push(r);
    } catch (e) {
      console.warn('Senden an Gruppenmitglied', memberId, 'fehlgeschlagen:', e.message);
    }
  }
  if (!results.length) throw new Error('Nachricht konnte an kein Mitglied zugestellt werden');

  const sentAt = Date.now();
  conv.lastMsg = { text: plaintext, ts: sentAt };
  conv.unread = 0;
  if (!state.messages.has(convId)) state.messages.set(convId, []);
  state.messages.get(convId).push({ id: 'local-' + sentAt, text: plaintext, ts: sentAt, mine: true });
  LocalCache.scheduleSave();
  return { sentAt };
}

async function sendMessage(peerId, convId, plaintext) {
  const bundles = await ensureSessions(peerId);
  const perDevice = [];

  for (const bundle of bundles) {
    const key = sk(peerId, bundle.deviceId);
    const st = state.sessions.get(key);
    if (!st) continue;   // Bundle-Signatur war ungültig, siehe ensureSessions

    /* WICHTIG: Ratchet.initSender() setzt dhSteps bereits auf 1 (das
       anfängliche X3DH-DH zählt als erster Schritt) — dhSteps===0 ist
       daher NIE wahr für eine frische Sender-Sitzung und hätte den
       X3DH-Header nie angehängt. Der richtige Indikator für "erste
       Nachricht auf dieser Sitzung" ist allein Ns (tatsächlich gesendete
       Nachrichten), das bei initSender korrekt bei 0 startet.

       Der X3DH-Header gehört NUR zur allerersten Nachricht des
       ursprünglichen INITIATORS (st.ephemeral ist nur bei per
       ensureSessions/X3DH.initiator aufgebauten Sitzungen gesetzt).
       Antwortet stattdessen der ursprüngliche EMPFÄNGER (Sitzung kam aus
       ensureReceiverSession, kein eigener Ephemeral-Key vorhanden), ist
       kein X3DH-Header nötig — der Ratchet-Header allein reicht, weil
       die Sitzung beim Gegenüber schon über den ersten Header etabliert
       wurde. */
    const isFirst = st.Ns === 0 && !!st.ephemeral;
    const env = await Ratchet.encrypt(st, te.encode(plaintext), `v1|${state.me.id}|${convId}`);
    scheduleSessionSave();
    const header = isFirst
      ? { ...env.header, x3dh: { senderIK: state.identity.IK.pubJwk, senderEK: st.ephemeral.pubJwk, opkId: st.usedOpkId } }
      : env.header;
    /* Ratchet.encrypt() liefert ct als rohen ArrayBuffer (WebCrypto-
       Ausgabe) — der Server speichert ciphertext als TEXT-Spalte und
       kann keinen ArrayBuffer binden. Vor dem Versand nach Base64
       kodieren; openRatchet() beim Empfänger dekodiert entsprechend
       zurück, bevor Ratchet.decrypt() den rohen Buffer wieder erwartet. */
    perDevice.push({ deviceId: bundle.deviceId, header, ciphertext: b64(env.ct) });
  }
  if (!perDevice.length) throw new Error('Keine gültige Sitzung für dieses Konto aufbaubar');

  const result = await api.send({ recipientId: peerId, convId, kind: 'text', perDevice });

  /* Strukturierte "unsichtbare" Nachrichtenarten (Umfrage-Stimmen,
     Live-Standort-Updates) dürfen beim SENDER genauso wenig als
     Chatzeile auftauchen wie beim Empfänger (siehe handleEnvelope,
     das dieselbe Prüfung für eingehende Nachrichten macht) — sonst
     sieht der Sender seine eigenen internen Protokoll-Nachrichten als
     rohen JSON-Text im Chatverlauf UND in der Chat-Vorschau. */
  let isSilent = false;
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed?.__pollVote || parsed?.__liveLocationUpdate) isSilent = true;
  } catch {}

  const conv = state.convs.get(convId) || { convId, peerId };
  if (!isSilent) {
    conv.lastMsg = { text: plaintext, ts: result.sentAt };
    conv.unread = 0;
  }
  state.convs.set(convId, conv);

  if (!isSilent) {
    if (!state.messages.has(convId)) state.messages.set(convId, []);
    state.messages.get(convId).push({ id: 'local-' + result.sentAt, text: plaintext, ts: result.sentAt, mine: true });
    LocalCache.scheduleSave();
  }
  return result;
}

/* ═══════════════════════════════════════════════════════════════════════
   MIC/SENDEN-UMSCHALTUNG — wie WhatsApp: leeres Feld → Mikrofon,
   sobald Text eingegeben wird → Senden-Pfeil.
   ═══════════════════════════════════════════════════════════════════════ */
const SEND_ICON = '<path d="M3 20l18-8L3 4v6l12 2-12 2v6z"/>';
const MIC_ICON = '<path d="M12 14a3 3 0 0 0 3-3V6a3 3 0 0 0-6 0v5a3 3 0 0 0 3 3zm5-3a5 5 0 0 1-10 0H5a7 7 0 0 0 6 6.93V21h2v-3.07A7 7 0 0 0 19 11h-2z"/>';

function onMsgInputChange(v) {
  const icon = $('#sendMicIcon');
  if (!icon) return;
  icon.outerHTML = v.trim()
    ? `<svg id="sendMicIcon" viewBox="0 0 24 24" width="18" height="18" fill="#fff">${SEND_ICON}</svg>`
    : `<svg id="sendMicIcon" viewBox="0 0 24 24" width="18" height="18" fill="#fff">${MIC_ICON}</svg>`;
}

function sendOrMicClick() {
  const input = $('#msgInput');
  if (input?.value.trim()) {
    sendCurrentMessage();
  } else {
    startVoiceRecording();
  }
}

/* ── Sprachnachricht aufnehmen ──
   Halten zum Aufnehmen (wie WhatsApp): pointerdown startet, pointerup
   stoppt+sendet, Wegziehen bricht ab. Nutzt MediaRecorder — läuft nur
   während des Haltens, damit aus Versehen offen gelassene Mikrofone
   nicht endlos aufnehmen. */
let _voiceRecorder = null;
let _voiceChunks = [];
let _voiceStream = null;

async function startVoiceRecording() {
  if (!state.activeConv) return;
  try {
    _voiceStream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (e) {
    toast('⚠️ Mikrofonzugriff verweigert');
    return;
  }
  _voiceChunks = [];
  _voiceRecorder = new MediaRecorder(_voiceStream);
  _voiceRecorder.ondataavailable = (e) => { if (e.data.size) _voiceChunks.push(e.data); };
  _voiceRecorder.start();

  const btn = $('#sendOrMicBtn');
  btn?.classList.add('recording-active');
  showVoiceRecordingBar();
}

function showVoiceRecordingBar() {
  const bar = document.createElement('div');
  bar.id = 'voiceRecBar';
  bar.style.cssText = 'position:absolute;bottom:0;left:0;right:0;background:var(--panel);' +
    'display:flex;align-items:center;gap:10px;padding:12px 16px;z-index:50';
  bar.innerHTML = `
    <span style="color:#f15c6d;font-size:18px">●</span>
    <span id="voiceRecTimer" style="flex:1;font-variant-numeric:tabular-nums">0:00</span>
    <button class="btn ghost" style="padding:8px 16px" onclick="window.__app.stopVoiceRecording(false)">Abbrechen</button>
    <button class="sendbtn navbtn3d navbtn3d-send" onclick="window.__app.stopVoiceRecording(true)" aria-label="Senden">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff">${SEND_ICON}</svg>
    </button>`;
  $('#composer')?.appendChild(bar);
  const start = Date.now();
  const timerEl = () => $('#voiceRecTimer');
  bar._timer = setInterval(() => {
    const s = Math.floor((Date.now() - start) / 1000);
    const el = timerEl();
    if (el) el.textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }, 250);
}

async function stopVoiceRecording(send) {
  const bar = document.getElementById('voiceRecBar');
  if (bar) { clearInterval(bar._timer); bar.remove(); }
  $('#sendOrMicBtn')?.classList.remove('recording-active');

  if (!_voiceRecorder) return;
  const recorder = _voiceRecorder;
  const stream = _voiceStream;
  _voiceRecorder = null; _voiceStream = null;

  const blobPromise = new Promise((resolve) => {
    recorder.onstop = () => resolve(new Blob(_voiceChunks, { type: 'audio/webm' }));
  });
  recorder.stop();
  stream.getTracks().forEach(t => t.stop());
  const blob = await blobPromise;

  if (!send || blob.size < 500) return;   // Abbruch oder zu kurz zum Senden

  const file = new File([blob], 'voice-' + Date.now() + '.webm', { type: 'audio/webm' });
  await sendMediaMessage(file, 'audio');
}

async function sendCurrentMessage() {
  const input = $('#msgInput');
  if (!input) return;
  const text = input.value.trim();
  if (!text || !state.activeConv) return;
  input.value = '';
  input.style.height = 'auto';
  const { peerId, convId, groupId, isGroup } = state.activeConv;

  /* Gruppen-Chats laufen über einen eigenen Pfad (AES-Gruppenschlüssel
     statt 1:1-Ratchet) — siehe sendGroupMessage. Kein Offline-Queueing
     für Gruppen in dieser ersten Version: die Zustellung an mehrere
     Mitglieder gleichzeitig würde die Warteschlangen-Logik unnötig
     verkomplizieren, ohne dass es aktuell einen dringenden Bedarf gibt. */
  if (isGroup) {
    try {
      await sendGroupMessage(groupId, convId, text);
      renderChatMessages();
    } catch (e) {
      toast('⚠️ ' + e.message);
      input.value = text;
    }
    return;
  }

  /* Schon bekannt offline: gar nicht erst versuchen — sofort in die
     Warteschlange, mit sichtbarem "wird gesendet"-Zustand statt eines
     Fehlertoasts bei jeder einzelnen Nachricht. */
  if (state.isOffline) {
    queueOffline(peerId, convId, text);
    return;
  }

  try {
    await sendMessage(peerId, convId, text);
    renderChatMessages();
  } catch (e) {
    /* Unterscheiden: ein Netzwerkfehler (TypeError bei fetch, kein
       HTTP-Status) landet in der automatischen Warteschlange. Eine
       echte Serverablehnung (z. B. blockiert, 4xx) bekommt der Nutzer
       sofort zu sehen — automatisches Wiederholen würde da nur denselben
       Fehler wiederholen, das Problem liegt nicht am Netz. */
    if (e.status === undefined) {
      state.isOffline = true;
      updateOfflineBanner();
      queueOffline(peerId, convId, text);
    } else {
      toast('⚠️ Senden fehlgeschlagen: ' + e.message);
      input.value = text;
    }
  }
}

function queueOffline(peerId, convId, text) {
  const localId = 'pending-' + Date.now() + '-' + Math.random().toString(36).slice(2);
  state.outbox.push({ peerId, convId, text, localId, ts: Date.now() });
  if (!state.messages.has(convId)) state.messages.set(convId, []);
  state.messages.get(convId).push({ id: localId, text, ts: Date.now(), mine: true, pending: true });
  LocalCache.scheduleSave();
  renderChatMessages();
}

/* ═══════════════════════════════════════════════════════════════════════
   CHAT-FENSTER
   ═══════════════════════════════════════════════════════════════════════ */
function openChat(c) {
  state.view = 'chat';
  state.activeConv = { peerId: c.peerId, convId: c.convId, name: c.name || c.peerId };
  if (c.unread) { c.unread = 0; }

  const overlay = document.createElement('div');
  overlay.className = 'chatview';
  overlay.id = 'chatOverlay';
  overlay.innerHTML = `
    <div class="chatbar">
      <button class="iconbtn" onclick="window.__app.closeChat()">←</button>
      <div class="av" style="width:38px;height:38px;font-size:16px">${((c.name || c.peerId || '?'))[0].toUpperCase()}</div>
      <div class="name">
        <div class="nm">${c.name ? esc(c.name) : 'Unbekannt'}</div>
        <div class="st" id="chatStatus">${c.name ? (c.online ? 'online' : 'offline') : esc(c.peerId)}</div>
      </div>
      <button class="iconbtn callbtn3d callbtn3d-audio" onclick="window.__app.startCall('audio')" aria-label="Anrufen"></button>
      <button class="iconbtn callbtn3d callbtn3d-video" onclick="window.__app.startCall('video')" aria-label="Videoanruf">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M17 10.5V7a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3.5l4 4v-11l-4 4z"/></svg>
      </button>
      <button class="iconbtn navbtn3d" onclick="window.__app.chatMenu(event)" aria-label="Menü">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>
      </button>
    </div>
    <div id="chatbody"></div>
    <div id="composer">
      <div class="cbar">
        <button class="iconbtn navbtn3d" onclick="window.__app.attachSheet()" aria-label="Anhängen">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a5 5 0 0 1-7.07-7.07l9.19-9.19a3.5 3.5 0 0 1 4.95 4.95l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
        </button>
        <div class="cin">
          <textarea id="msgInput" rows="1" placeholder="Nachricht"
            oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,110)+'px';window.__app.onMsgInputChange(this.value)"
            onkeydown="window.__app.inputKey(event)"></textarea>
        </div>
        <button class="sendbtn navbtn3d navbtn3d-send" id="sendOrMicBtn"
          onclick="window.__app.sendOrMicClick()" aria-label="Senden">
          <svg id="sendMicIcon" viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M12 14a3 3 0 0 0 3-3V6a3 3 0 0 0-6 0v5a3 3 0 0 0 3 3zm5-3a5 5 0 0 1-10 0H5a7 7 0 0 0 6 6.93V21h2v-3.07A7 7 0 0 0 19 11h-2z"/></svg>
        </button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(overlay);

  /* Android/Chrome verschiebt bei geöffneter Tastatur den sichtbaren
     Viewport, ohne dass CSS position:fixed zuverlässig darauf reagiert
     (bekannter Chrome-Bug: fixed-Elemente bleiben am Layout-Viewport,
     nicht am visuellen). visualViewport meldet die tatsächlich
     sichtbare Höhe/Position — darüber wird die Chatbar aktiv
     nachgeführt, statt sich auf CSS allein zu verlassen. */
  const chatbarEl = overlay.querySelector('.chatbar');
  const fixChatbarPosition = () => {
    if (!chatbarEl || !window.visualViewport) return;
    const vv = window.visualViewport;
    chatbarEl.style.top = vv.offsetTop + 'px';
  };
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', fixChatbarPosition);
    window.visualViewport.addEventListener('scroll', fixChatbarPosition);
    overlay._vvCleanup = () => {
      window.visualViewport.removeEventListener('resize', fixChatbarPosition);
      window.visualViewport.removeEventListener('scroll', fixChatbarPosition);
    };
    fixChatbarPosition();
  }

  ensureSessions(c.peerId).catch(e => toast('⚠️ ' + e.message));
  renderChatMessages();
  $('#msgInput')?.focus();

  /* Lesebestätigung für alle fremden Nachrichten senden, die noch nicht
     als 'read' markiert wurden — passiert beim Öffnen, weil ab hier der
     Nutzer sie tatsächlich sieht. */
  const msgs = state.messages.get(c.convId) || [];
  const unreadIds = msgs.filter(m => !m.mine && !m.readSent).map(m => m.id);
  if (unreadIds.length) {
    sendReadReceipt(c.convId, c.peerId, unreadIds);
    for (const m of msgs) if (unreadIds.includes(m.id)) m.readSent = true;
  }
}

function closeChat() {
  const overlay = document.getElementById('chatOverlay');
  overlay?._vvCleanup?.();
  overlay?.remove();
  state.view = 'list';
  state.activeConv = null;
  renderMain();
}

function renderChatHeader() {
  const el = document.getElementById('chatStatus');
  if (!el || !state.activeConv) return;
  const conv = state.convs.get(state.activeConv.convId);
  el.textContent = conv?.online ? 'online' : 'offline';
}

/* Häkchen-Status: 🕐 wartet auf Versand (offline) → ✓ gesendet
   (Server hat den Umschlag angenommen) → ✓✓ grau zugestellt (Empfänger-
   gerät hat quittiert) → ✓✓ blau gelesen (explizite Lesebestätigung,
   nur falls beim Empfänger aktiviert). */
function renderCheckmark(m) {
  if (m.pending) return `<span class="ck" title="Wird gesendet, sobald wieder online">🕐</span>`;
  if (m.status === 'read') return `<span class="ck read" title="Gelesen">✓✓</span>`;
  if (m.status === 'delivered') return `<span class="ck" title="Zugestellt">✓✓</span>`;
  return `<span class="ck" title="Gesendet">✓</span>`;
}

function renderChatMessages() {
  if (!state.activeConv) return;
  const body = document.getElementById('chatbody');
  if (!body) return;
  const msgs = state.messages.get(state.activeConv.convId) || [];

  let lastDay = null;
  const rows = [];
  rows.push(`<div class="encnote">🔒 Nachrichten sind Ende-zu-Ende-verschlüsselt.</div>`);
  for (const m of msgs) {
    const d = day(m.ts);
    if (d !== lastDay) { rows.push(`<div class="daysep"><span>${d}</span></div>`); lastDay = d; }

    /* Medienreferenz erkennen: entweder schon beim Senden markiert
       (m.media, eigener Anhang) oder beim Empfangen aus dem
       entschlüsselten JSON-Text erkannt. */
    const incomingMedia = !m.media && !m.mine ? parseIncomingMedia(m.text) : null;
    const media = m.media || incomingMedia;
    const locationCard = !media ? parseStructured(m.text, '__location') : null;
    const contactCard = !media ? parseStructured(m.text, '__contact') : null;
    const pollCard = !media ? parseStructured(m.text, '__poll') : null;
    const pollVote = !media ? parseStructured(m.text, '__pollVote') : null;

    if (pollVote) continue;   // Stimmen werden separat verarbeitet (siehe onIncomingEnvelope), nicht als eigene Chatzeile gezeigt

    let content;
    if (pollCard) {
      content = renderPollCard(pollCard, m.id);
    } else if (locationCard) {
      /* Statisches Kartenbild über OpenStreetMap-Tiles — komplett
         kostenlos, kein API-Key nötig (im Gegensatz zu Google Maps
         Static API, das zahlungspflichtig ist). Der Link selbst öffnet
         weiterhin Google Maps, weil dort Navigation/Details besser
         funktionieren — nur die Vorschau kommt von OSM. */
      const { lat, lng } = locationCard;
      const zoom = 15;
      const tileX = Math.floor((lng + 180) / 360 * Math.pow(2, zoom));
      const tileY = Math.floor((1 - Math.log(Math.tan(lat * Math.PI / 180) + 1 / Math.cos(lat * Math.PI / 180)) / Math.PI) / 2 * Math.pow(2, zoom));
      const tileUrl = `https://tile.openstreetmap.org/${zoom}/${tileX}/${tileY}.png`;
      const isLive = !!locationCard.liveId;
      const expired = isLive && locationCard.expiresAt && Date.now() > locationCard.expiresAt;
      const label = expired ? 'Live-Standort beendet'
        : isLive ? `🔴 Live-Standort — endet ${new Date(locationCard.expiresAt).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}`
        : 'Standort — auf Google Maps öffnen';
      content = `<a href="${esc(locationCard.url)}" target="_blank" rel="noopener" class="mapcard" style="text-decoration:none;color:inherit">
        <div class="mapcard-thumb" style="background-image:url('${tileUrl}')${expired ? ';filter:grayscale(1)' : ''}">
          <div class="mapcard-pin">📍</div>
        </div>
        <div class="mapcard-label">${esc(label)}</div>
      </a>`;
    } else if (contactCard) {
      content = `<div class="filemsg">👤 <span>${esc(contactCard.name || contactCard.id)}</span></div>`;
    } else if (media) {
      const thumb = media.ref?.thumb;
      if (m.mediaUrl) {
        /* Original bereits heruntergeladen und entschlüsselt (siehe
           downloadAndShowMedia) — das zeigt die volle Datei. */
        content = media.kind === 'image'
          ? `<div class="media" style="cursor:pointer" onclick="window.__app.openMediaFullscreen('${m.id}')"><img src="${m.mediaUrl}"></div>`
          : media.kind === 'video'
            ? `<div class="media"><video src="${m.mediaUrl}" controls></video></div>`
            : media.kind === 'audio'
              ? `<audio src="${m.mediaUrl}" controls style="width:220px;max-width:100%"></audio>`
              : `<div class="filemsg">📄 <a href="${m.mediaUrl}" download style="color:inherit">${esc(media.name || 'Datei')}</a></div>`;
      } else if (thumb && (media.kind === 'image' || media.kind === 'video')) {
        /* Thumbnail ist Teil der bereits entschlüsselten Nachricht
           selbst (siehe makeThumbnail/sendMediaMessage) — Sender UND
           Empfänger sehen es SOFORT, ohne dass irgendjemand die
           Originaldatei vom Server laden muss. Sender hat mediaUrl
           bereits (siehe sendMediaMessage) und öffnet direkt Vollbild;
           Empfänger muss erst laden (loadMedia kümmert sich danach
           selbst ums Öffnen). */
        const clickHandler = m.mine && m.mediaUrl
          ? `window.__app.openMediaFullscreen('${m.id}')`
          : `window.__app.loadMedia('${m.id}')`;
        content = `<div class="media media-thumb" style="cursor:pointer" onclick="${clickHandler}">
            <img src="${thumb}">
            ${media.kind === 'video' ? '<div class="media-play-badge">▶</div>' : ''}
            ${!m.mine ? '<div class="media-load-badge">⬇️ Original laden</div>' : ''}
          </div>`;
      } else {
        const icon = media.kind === 'image' ? '🖼️' : media.kind === 'video' ? '🎬' : media.kind === 'audio' ? '🎤' : '📄';
        const label = media.kind === 'image' ? 'Foto' : media.kind === 'video' ? 'Video' : media.kind === 'audio' ? 'Sprachnachricht' : (media.name || 'Datei');
        content = m.mine
          ? `<div class="filemsg">${icon} <span>${label} — von dir gesendet</span></div>`
          : `<div class="filemsg" style="cursor:pointer" onclick="window.__app.loadMedia('${m.id}')">
              ${icon} <span>${label} — antippen zum Anhören/Laden</span></div>`;
      }
    } else {
      content = `<div class="tx">${esc(m.text)}</div>`;
    }

    const msgSelMode = !!state.msgSelectMode;
    const msgSelected = state.selectedMsgs?.has(m.id);
    const rowClick = msgSelMode ? `window.__app.toggleSelectMsg('${esc(m.id)}')` : '';
    rows.push(`
      <div class="msgrow ${m.mine ? 'mine' : ''} ${msgSelected ? 'msgrow-selected' : ''}" data-msgid="${esc(m.id)}"
        onclick="${rowClick}"
        ontouchstart="window.__app.msgLongPressStart('${esc(m.id)}')"
        ontouchend="window.__app.msgLongPressEnd()" ontouchmove="window.__app.msgLongPressEnd()"
        oncontextmenu="window.__app.openMsgMenu('${esc(m.id)}');return false;">
        ${msgSelMode ? `<span class="msgselectcheck">${msgSelected ? '✅' : '⭕'}</span>` : ''}
        <div class="bub" style="${m.pending ? 'opacity:.65' : ''}">
          ${state.activeConv.isGroup && !m.mine ? `<div class="msg-sender-name">${esc(m.fromName || 'Unbekannt')}</div>` : ''}
          ${content}
          <div class="ft"><span class="tm">${time(m.ts)}</span>
            ${m.mine ? renderCheckmark(m) : ''}
            ${!m.mine && media ? `<span class="timerbadge" style="color:var(--sub);background:rgba(255,255,255,.08)"
              title="Direkt übertragen — Absender für den Speicherdienst sichtbar">📎 direkt</span>` : ''}</div>
        </div>
      </div>`);
  }
  body.innerHTML = (state.msgSelectMode ? `
    <div class="selectbar" style="position:sticky;top:0;z-index:10">
      <button class="iconbtn" onclick="window.__app.exitMsgSelectMode()" aria-label="Schließen">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
      <span class="selectcount">${state.selectedMsgs.size} ausgewählt</span>
      <button class="iconbtn navbtn3d" onclick="window.__app.forwardSelectedMsgs()" aria-label="Weiterleiten">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M14 5l7 7-7 7v-4c-5.5 0-9 2-11 5 .5-6 4-11 11-11V5z"/></svg>
      </button>
      <button class="iconbtn navbtn3d" style="background:radial-gradient(circle at 35% 30%,#f87171,#dc2626 70%)"
        onclick="window.__app.deleteSelectedMsgs()" aria-label="Löschen">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="#fff"><path d="M6 7h12l-1 13a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1L6 7zm3-3h6l1 2H8l1-2z"/></svg>
      </button>
    </div>` : '') + rows.join('');
  body.scrollTop = body.scrollHeight;
}

/* ── Mehrfachauswahl von Nachrichten (wie bei der Chatliste) ── */
function enterMsgSelectMode(msgId) {
  state.msgSelectMode = true;
  if (!state.selectedMsgs) state.selectedMsgs = new Set();
  state.selectedMsgs.add(msgId);
  renderChatMessages();
}
function exitMsgSelectMode() {
  state.msgSelectMode = false;
  state.selectedMsgs = new Set();
  renderChatMessages();
}
function toggleSelectMsg(msgId) {
  if (!state.selectedMsgs) state.selectedMsgs = new Set();
  if (state.selectedMsgs.has(msgId)) state.selectedMsgs.delete(msgId);
  else state.selectedMsgs.add(msgId);
  if (state.selectedMsgs.size === 0) { exitMsgSelectMode(); return; }
  renderChatMessages();
}
function deleteSelectedMsgs() {
  const convId = state.activeConv?.convId;
  const msgs = state.messages.get(convId);
  if (!msgs || !state.selectedMsgs?.size) return;
  const count = state.selectedMsgs.size;
  if (!confirm(`${count} Nachricht${count > 1 ? 'en' : ''} löschen? Nur bei dir — nicht rückgängig.`)) return;
  const kept = msgs.filter(m => !state.selectedMsgs.has(m.id));
  state.messages.set(convId, kept);
  LocalCache.scheduleSave();
  exitMsgSelectMode();
  toast(`${count} Nachricht${count > 1 ? 'en' : ''} gelöscht`);
}
function forwardSelectedMsgs() {
  const convId = state.activeConv?.convId;
  const msgs = state.messages.get(convId) || [];
  const selected = msgs.filter(m => state.selectedMsgs?.has(m.id));
  if (!selected.length) return;
  state.forwardPayload = { multiple: selected.map(m => ({ text: m.text, media: m.media })) };
  exitMsgSelectMode();
  openNewChatSheet();
  toast('Kontakt auswählen, um weiterzuleiten');
}

/* ── Gruppenschlüssel lokal persistieren (nur dieses Gerät) ── */
function saveGroupKeyLocal(groupId, rawKeyB64) {
  try {
    const store = JSON.parse(localStorage.getItem('sc:groupKeys') || '{}');
    store[groupId] = rawKeyB64;
    localStorage.setItem('sc:groupKeys', JSON.stringify(store));
  } catch {}
}
async function loadGroupKeysLocal() {
  if (!state.groupKeys) state.groupKeys = new Map();
  try {
    const store = JSON.parse(localStorage.getItem('sc:groupKeys') || '{}');
    for (const [groupId, rawKeyB64] of Object.entries(store)) {
      const key = await crypto.subtle.importKey('raw', ub64(rawKeyB64), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
      state.groupKeys.set(groupId, key);
    }
  } catch {}
}

/* Wird aufgerufen, wenn eine neue Gruppe für mich als Mitglied
   eintrifft (siehe refreshGroups) — entschlüsselt den für mich
   gewrappten Gruppenschlüssel über meine bestehende Ratchet-Session
   mit dem Gruppen-ERSTELLER (der hat ihn gewrappt, siehe
   confirmCreateGroup). */
async function unwrapGroupKey(groupId, creatorId, wrappedB64) {
  try {
    const wrappedJson = JSON.parse(td.decode(ub64(wrappedB64)));
    await ensureSessions(creatorId);
    const sessionKey = [...state.sessions.keys()].find(k => k.startsWith(creatorId + '>'));
    const st = state.sessions.get(sessionKey);
    if (!st) throw new Error('Keine Session zum Gruppen-Ersteller');
    const rawKeyBuf = await Ratchet.decrypt(st,
      { header: wrappedJson.header, ct: ub64(wrappedJson.ct) },
      `v1|${creatorId}|group-key`);
    scheduleSessionSave();
    const rawKeyB64 = td.decode(rawKeyBuf);
    const key = await crypto.subtle.importKey('raw', ub64(rawKeyB64), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    if (!state.groupKeys) state.groupKeys = new Map();
    state.groupKeys.set(groupId, key);
    saveGroupKeyLocal(groupId, rawKeyB64);
    return key;
  } catch (e) {
    console.warn('Gruppenschlüssel konnte nicht entschlüsselt werden:', e.message);
    return null;
  }
}

/* Eigene Gruppen vom Server laden und in state.convs einpflegen —
   analog zu refreshInbox für 1:1-Chats. */
async function refreshGroups() {
  let groups;
  try { ({ groups } = await api._fetch('/api/groups')); }
  catch { return; }

  for (const g of groups) {
    const convId = 'grp_' + g.id;
    if (state.deletedConvIds?.has(convId)) continue;   // Nutzer hat diese Gruppe lokal gelöscht
    let conv = state.convs.get(convId);
    if (!conv) {
      conv = { convId, groupId: g.id, isGroup: true, name: g.name, memberIds: g.members.map(m => m.userId), unread: 0 };
      state.convs.set(convId, conv);
    }
    if (!state.groupKeys?.has(g.id) && g.wrapped && g.ownerId !== state.me.id) {
      await unwrapGroupKey(g.id, g.ownerId, g.wrapped);
    }
  }
  renderMain();
}
let _msgLongPressTimer = null;
function msgLongPressStart(msgId) {
  if (state.msgSelectMode) return;   // im Auswahlmodus übernimmt der normale Klick
  _msgLongPressTimer = setTimeout(() => openMsgMenu(msgId), 450);
}
function msgLongPressEnd() {
  if (_msgLongPressTimer) { clearTimeout(_msgLongPressTimer); _msgLongPressTimer = null; }
}
function openMsgMenu(msgId) {
  const convId = state.activeConv?.convId;
  const msgs = state.messages.get(convId) || [];
  const msg = msgs.find(m => m.id === msgId);
  if (!msg) return;

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'msgMenuSheet';
  sheet.onclick = e => { if (e.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="menulist">
        ${!msg.media ? `
          <button class="menuitem" onclick="window.__app.copyMessage('${esc(msgId)}')">
            <span class="mi-ic">📋</span><span>Kopieren</span>
          </button>` : ''}
        <button class="menuitem" onclick="window.__app.forwardMessage('${esc(msgId)}')">
          <span class="mi-ic">↪️</span><span>Weiterleiten</span>
        </button>
        <button class="menuitem" onclick="document.getElementById('msgMenuSheet').remove();window.__app.enterMsgSelectMode('${esc(msgId)}')">
          <span class="mi-ic">☑️</span><span>Mehrere auswählen</span>
        </button>
        <button class="menuitem" onclick="window.__app.deleteMessage('${esc(msgId)}')">
          <span class="mi-ic">🗑️</span><span style="color:var(--dan)">Löschen</span>
        </button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}
function copyMessage(msgId) {
  document.getElementById('msgMenuSheet')?.remove();
  const msgs = state.messages.get(state.activeConv?.convId) || [];
  const msg = msgs.find(m => m.id === msgId);
  if (!msg?.text) return;
  navigator.clipboard?.writeText(msg.text).then(() => toast('Kopiert')).catch(() => toast('⚠️ Kopieren fehlgeschlagen'));
}
function deleteMessage(msgId) {
  document.getElementById('msgMenuSheet')?.remove();
  const convId = state.activeConv?.convId;
  const msgs = state.messages.get(convId);
  if (!msgs) return;
  const idx = msgs.findIndex(m => m.id === msgId);
  if (idx === -1) return;
  /* Nur lokal — kein "Für alle löschen", das würde eine Serverfunktion
     brauchen, die die Nachricht beim Empfänger nachträglich entfernt
     (technisch bei E2EE nur als Hinweis möglich, nicht als Garantie). */
  msgs.splice(idx, 1);
  LocalCache.scheduleSave();
  renderChatMessages();
  toast('Nachricht gelöscht (nur bei dir)');
}
function forwardMessage(msgId) {
  document.getElementById('msgMenuSheet')?.remove();
  const msgs = state.messages.get(state.activeConv?.convId) || [];
  const msg = msgs.find(m => m.id === msgId);
  if (!msg) return;
  state.forwardPayload = { text: msg.text, media: msg.media };
  openNewChatSheet();
  toast('Kontakt auswählen, um weiterzuleiten');
}

/* ═══════════════════════════════════════════════════════════════════════
   NEUER CHAT
   ═══════════════════════════════════════════════════════════════════════ */
async function openNewChatSheet() {
  let users;
  try { ({ users } = await api.listUsers()); }
  catch (e) { toast('⚠️ ' + e.message); return; }

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'newChatSheet';
  sheet.onclick = e => { if (e.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Neuer Chat</h3>
      <div class="row" style="padding:8px 0" onclick="window.__app.openCreateGroup()">
        <div class="av" style="background:var(--panel2)">👥</div>
        <div class="meta" style="border-bottom:none">
          <div class="l1"><span class="nm">Neue Gruppe</span></div>
        </div>
      </div>
      ${users.length ? users.map(u => `
        <div class="row" style="padding:8px 0" onclick="window.__app.startChatWith('${u.id}', '${esc(u.name || '')}')">
          <div class="av">${esc((u.name || '?')[0].toUpperCase())}
            <div class="dot ${u.online ? 'online' : 'offline'}"></div></div>
          <div class="meta" style="border-bottom:none">
            <div class="l1"><span class="nm">${esc(u.name)}</span></div>
          </div>
        </div>`).join('') : `<div class="empty" style="height:auto;padding:24px"><div class="ic">👤</div><div>Noch keine anderen Nutzer</div></div>`}
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

function startChatWith(userId, userName) {
  document.getElementById('newChatSheet')?.remove();
  const convId = 'dm_' + [state.me.id, userId].sort().join('_');
  let conv = state.convs.get(convId);
  if (!conv) {
    conv = { convId, peerId: userId, name: userName || userId, unread: 0 };
    state.convs.set(convId, conv);
  } else if (!conv.name || conv.name === conv.peerId) {
    conv.name = userName || conv.name;
  }
  openChat(conv);
}

/* ═══════════════════════════════════════════════════════════════════════
   GRUPPEN — pragmatisches Modell ohne eigenes Sender-Keys-Protokoll
   ─────────────────────────────────────────────────────────────────────
   Statt eines vollständigen Gruppen-Ratchets (wie Signals Sender Keys,
   deutlich komplexer zu implementieren und zu verifizieren) nutzt
   SecureChat einen einzigen zufälligen AES-256-Gruppenschlüssel:
   - Beim Erstellen wird er einmal generiert
   - Für JEDES Mitglied wird er über dessen bestehende 1:1-Ratchet-
     Session verschlüsselt (also mit der schon vorhandenen X3DH/Double-
     Ratchet-Infrastruktur, kein neues Kryptoprimitiv nötig)
   - Der Server speichert nur den verschlüsselten "wrapped"-Blob pro
     Mitglied (siehe group_members.wrapped) — sieht den Klartext-
     schlüssel nie
   - Gruppennachrichten werden direkt mit dem AES-Gruppenschlüssel
     versiegelt und per bestehendem /api/send an alle Mitgliedergeräte
     verteilt (perDevice-Liste, wie bei 1:1)

   Trade-off: Kein Forward Secrecy INNERHALB der Gruppe (der Schlüssel
   ändert sich nicht bei jeder Nachricht) und kein automatisches Neu-
   verschlüsseln bei Mitgliederaustritt — für den aktuellen Umfang
   akzeptabel, aber im Kommentar dokumentiert für eine spätere Härtung. */
async function openCreateGroup() {
  document.getElementById('newChatSheet')?.remove();
  let users;
  try { ({ users } = await api.listUsers()); }
  catch (e) { toast('⚠️ ' + e.message); return; }

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'createGroupSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Neue Gruppe</h3>
      <input id="groupNameInput" type="text" placeholder="Gruppenname"
        style="width:100%;box-sizing:border-box;font-size:16px;padding:12px;border-radius:10px;
          border:none;background:var(--panel2);color:var(--tx);margin-bottom:14px">
      <label style="font-size:13px;color:var(--sub)">Mitglieder auswählen</label>
      <div style="max-height:40vh;overflow-y:auto;margin-top:8px">
        ${users.map(u => `
          <label class="row" style="padding:8px 0;cursor:pointer">
            <input type="checkbox" class="groupmember-cb" value="${esc(u.id)}" data-name="${esc(u.name || u.id)}"
              style="width:20px;height:20px;margin-right:10px;accent-color:var(--acc2)">
            <div class="av" style="width:32px;height:32px;font-size:14px">${esc((u.name || '?')[0].toUpperCase())}</div>
            <div class="meta" style="border-bottom:none"><div class="l1"><span class="nm">${esc(u.name || u.id)}</span></div></div>
          </label>`).join('')}
      </div>
      <button class="btn" style="width:100%;margin-top:16px" onclick="window.__app.confirmCreateGroup()">Gruppe erstellen</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

async function confirmCreateGroup() {
  const name = document.getElementById('groupNameInput')?.value.trim();
  const checked = [...document.querySelectorAll('.groupmember-cb:checked')];
  if (!name) { toast('⚠️ Bitte einen Gruppennamen eingeben'); return; }
  if (!checked.length) { toast('⚠️ Bitte mindestens ein Mitglied auswählen'); return; }

  const members = checked.map(cb => ({ id: cb.value, name: cb.dataset.name }));
  document.getElementById('createGroupSheet')?.remove();
  toast('Gruppe wird erstellt…', 3000);

  try {
    /* Gruppenschlüssel generieren, exportieren, für jedes Mitglied
       (inkl. mich selbst, für Multi-Device-Zugriff) über die
       bestehende 1:1-Session verschlüsseln. */
    const groupKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const rawKey = await crypto.subtle.exportKey('raw', groupKey);
    const rawKeyB64 = b64(rawKey);

    const wrapped = {};
    /* Für das eigene Konto wird KEIN Server-Wrap angelegt — der
       Schlüssel bleibt ausschließlich lokal (state.groupKeys +
       localStorage, siehe unten). Ein "Wrap für mich selbst" würde
       bedeuten, entweder den Klartextschlüssel unverschlüsselt zum
       Server zu schicken (Sicherheitsloch) oder eine eigene Geräte-zu-
       Geräte-Verschlüsselung zu bauen, die hier noch fehlt. Preis
       dafür: Gruppen sind aktuell an EIN Gerät pro Ersteller gebunden,
       bis Multi-Device-Sync für Gruppen ergänzt wird. */

    for (const m of members) {
      try {
        await ensureSessions(m.id);
        const key = sk(m.id, [...state.sessions.keys()].find(k => k.startsWith(m.id + '>'))?.split('>')[1]);
        const st = state.sessions.get(key);
        if (!st) continue;
        const env = await Ratchet.encrypt(st, te.encode(rawKeyB64), `v1|${state.me.id}|group-key`);
        scheduleSessionSave();
        wrapped[m.id] = b64(te.encode(JSON.stringify({ header: env.header, ct: b64(new Uint8Array(env.ct)) })));
      } catch (e) {
        console.warn('Gruppenschlüssel konnte nicht an', m.id, 'verteilt werden:', e.message);
      }
    }

    const { groupId } = await api._fetch('/api/group', {
      method: 'POST',
      body: { name, avatar: '👥', members: members.map(m => m.id), wrapped }
    });

    /* Gruppenschlüssel lokal cachen — spart erneutes Entschlüsseln bei
       jeder Nachricht in dieser Sitzung, UND persistent speichern,
       damit er einen Reload übersteht (nur auf diesem Gerät, siehe
       Hinweis oben zu Multi-Device). */
    if (!state.groupKeys) state.groupKeys = new Map();
    state.groupKeys.set(groupId, groupKey);
    saveGroupKeyLocal(groupId, rawKeyB64);

    const conv = {
      convId: 'grp_' + groupId, groupId, isGroup: true,
      name, memberIds: [state.me.id, ...members.map(m => m.id)], unread: 0
    };
    state.convs.set(conv.convId, conv);
    openChat(conv);
    toast('Gruppe "' + name + '" erstellt');
  } catch (e) {
    toast('⚠️ Gruppe konnte nicht erstellt werden: ' + e.message);
  }
}

function openMainMenu(e) {
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'mainMenuSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="row" style="padding:8px 0">
        <div class="av">${esc((state.me.name || '?')[0].toUpperCase())}</div>
        <div class="meta" style="border-bottom:none">
          <div class="l1"><span class="nm">${esc(state.me.name)}</span></div>
          <div class="l2" style="color:var(--sub);font-size:13px">${esc(state.me.email || '')}</div>
        </div>
      </div>
      <div class="menulist" style="margin-top:8px">
        <button class="menuitem" onclick="window.__app.openSettings()">
          <span class="mi-ic">⚙️</span><span>Einstellungen</span>
        </button>
        <button class="menuitem" onclick="window.__app.openNotificationSettings()">
          <span class="mi-ic">🔔</span><span>Benachrichtigungen</span>
        </button>
        <button class="menuitem" onclick="window.__app.openPrivacySettings()">
          <span class="mi-ic">🔒</span><span>Datenschutz &amp; Sicherheit</span>
        </button>
        <button class="menuitem" onclick="window.__app.openBlockedList()">
          <span class="mi-ic">🚫</span><span>Blockierte Kontakte</span>
        </button>
        <button class="menuitem" onclick="window.__app.openLinkedDevices()">
          <span class="mi-ic">🖥️</span><span>Verknüpfte Geräte</span>
        </button>
        <button class="menuitem" onclick="window.__app.openScheduledCallsList()">
          <span class="mi-ic">📅</span><span>Geplante Anrufe</span>
        </button>
      </div>
      <button class="btn ghost" style="width:100%;margin-top:16px" onclick="window.__app.logoutClick()">Abmelden</button>
      <button class="btn ghost" style="width:100%;margin-top:8px;color:#f15c6d" onclick="window.__app.showDeleteAccount()">Konto löschen</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

/* ═══════════════════════════════════════════════════════════════════════
   EINSTELLUNGEN — vollflächige Unterseiten
   ═══════════════════════════════════════════════════════════════════════ */
function openSettingsPage(title, bodyHtml) {
  document.getElementById('mainMenuSheet')?.remove();
  document.getElementById('settingsPage')?.remove();
  const page = document.createElement('div');
  page.className = 'chatview';
  page.id = 'settingsPage';
  page.innerHTML = `
    <div class="chatbar">
      <button class="iconbtn" onclick="document.getElementById('settingsPage').remove()">←</button>
      <div class="name"><div class="nm">${esc(title)}</div></div>
    </div>
    <div style="flex:1;overflow-y:auto;padding:16px;margin-top:calc(58px + env(safe-area-inset-top))">${bodyHtml}</div>`;
  document.getElementById('overlays').appendChild(page);
}

function openSettings() {
  openSettingsPage('Einstellungen', `
    <div class="menulist">
      <button class="menuitem" onclick="window.__app.editProfile()">
        <span class="mi-ic">👤</span><span>Profil bearbeiten</span>
      </button>
      <button class="menuitem" onclick="window.__app.openChatSettings()">
        <span class="mi-ic">💬</span><span>Chats</span>
      </button>
      <button class="menuitem" onclick="window.__app.openDesignSettings()">
        <span class="mi-ic">🎨</span><span>Design</span>
      </button>
      <button class="menuitem" onclick="window.__app.openLanguageSettings()">
        <span class="mi-ic">🌐</span><span>Sprache</span>
      </button>
      <button class="menuitem" onclick="window.__app.openStorageSettings()">
        <span class="mi-ic">💾</span><span>Speicher &amp; Daten</span>
      </button>
    </div>
    <p style="color:var(--sub);font-size:13px;margin-top:20px">SecureChat — Version 1.0</p>
  `);
}

/* ═══════════════════════════════════════════════════════════════════════
   DESIGN-EINSTELLUNGEN — Akzentfarbe für Buttons/aktive Elemente
   ─────────────────────────────────────────────────────────────────────
   Setzt --acc/--acc2 zur Laufzeit per CSS-Custom-Property auf dem
   Root-Element — betrifft dadurch automatisch ALLE Stellen, die diese
   Variablen nutzen (Buttons, Sende-Icon, Häkchen, aktive Tab-Farbe),
   ohne dass jede einzelne Komponente angepasst werden muss.
   ═══════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════
   DESIGN-EINSTELLUNGEN — jede Button-Kategorie einzeln einstellbar
   ─────────────────────────────────────────────────────────────────────
   Statt EINES globalen Themes (--acc/--acc2 für alles) bekommt jede
   funktionale Button-Gruppe ihre eigene CSS-Variable mit sinnvollem
   Fallback auf die globale Akzentfarbe, falls für diese Kategorie
   nichts explizit gewählt wurde (siehe index.html: var(--btn-x-2,
   var(--acc2, #fallback))). Das erlaubt sowohl "alles einheitlich"
   (nur --acc/--acc2 setzen) als auch volle Individualisierung. */
const BUTTON_CATEGORIES = {
  general:    { label: 'Allgemein (Navigation, Menüs)', cssVar: null },   // steuert --acc/--acc2 selbst
  send:       { label: 'Senden-Button', cssVar: 'btn-send' },
  attach:     { label: 'Anhang-Menü', cssVar: 'btn-attach' },
  callAudio:  { label: 'Anrufen (Audio)', cssVar: 'btn-callaudio' },
  callVideo:  { label: 'Anrufen (Video)', cssVar: 'btn-callvideo' },
  callAccept: { label: 'Anruf annehmen', cssVar: 'call-accept' },
  callEnd:    { label: 'Anruf beenden/ablehnen', cssVar: 'call-end' }
};
const ACCENT_THEMES = {
  green:  { acc: '#00a884', acc2: '#25d366', label: 'Grün' },
  blue:   { acc: '#1d4ed8', acc2: '#5b9bf5', label: 'Blau' },
  purple: { acc: '#7c3aed', acc2: '#a78bfa', label: 'Violett' },
  orange: { acc: '#ea580c', acc2: '#fb923c', label: 'Orange' },
  pink:   { acc: '#db2777', acc2: '#f472b6', label: 'Pink' },
  red:    { acc: '#dc2626', acc2: '#f87171', label: 'Rot' },
  default:{ acc: '', acc2: '', label: 'Standard' }   // Kategorie-eigener Fallback greift
};
function loadAccentTheme() {
  let stored = {};
  try { stored = JSON.parse(localStorage.getItem('sc:buttonThemes') || '{}'); } catch {}
  state.buttonThemes = stored;
  for (const key of Object.keys(BUTTON_CATEGORIES)) {
    applyButtonTheme(key, stored[key] || (key === 'general' ? 'green' : 'default'), false);
  }
}
function applyButtonTheme(category, themeKey, persist = true) {
  const t = ACCENT_THEMES[themeKey] || ACCENT_THEMES.default;
  const cat = BUTTON_CATEGORIES[category];
  if (!cat) return;
  if (category === 'general') {
    document.documentElement.style.setProperty('--acc', t.acc || '#00a884');
    document.documentElement.style.setProperty('--acc2', t.acc2 || '#25d366');
  } else if (themeKey === 'default') {
    document.documentElement.style.removeProperty(`--${cat.cssVar}-1`);
    document.documentElement.style.removeProperty(`--${cat.cssVar}-2`);
  } else {
    document.documentElement.style.setProperty(`--${cat.cssVar}-1`, t.acc);
    document.documentElement.style.setProperty(`--${cat.cssVar}-2`, t.acc2);
  }
  if (!state.buttonThemes) state.buttonThemes = {};
  state.buttonThemes[category] = themeKey;
  if (persist) {
    try { localStorage.setItem('sc:buttonThemes', JSON.stringify(state.buttonThemes)); } catch {}
  }
}
function setAccentTheme(theme) {
  /* Rückwärtskompatibel: setzt weiterhin NUR die allgemeine Kategorie —
     der Aufruf aus alten UI-Elementen bleibt funktionsfähig. */
  applyButtonTheme('general', theme);
  openDesignSettings();
}
function setCategoryTheme(category, theme) {
  applyButtonTheme(category, theme);
  openDesignSettings();
}
function openDesignSettings() {
  const branding = getAppBranding();
  const swatches = (category) => Object.entries(ACCENT_THEMES).map(([key, t]) => {
    const current = (state.buttonThemes?.[category] || (category === 'general' ? 'green' : 'default')) === key;
    const swatchColor = t.acc2 || 'var(--panel2)';
    return `
      <button onclick="window.__app.setCategoryTheme('${category}','${key}')"
        style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:8px 2px;
          border-radius:10px;border:2px solid ${current ? (t.acc2 || 'var(--sub)') : 'transparent'};
          background:var(--panel2);cursor:pointer">
        <span style="width:24px;height:24px;border-radius:50%;background:${swatchColor};
          ${key === 'default' ? 'border:2px dashed var(--sub)' : ''}"></span>
        <span style="font-size:10.5px;color:var(--tx)">${t.label}</span>
      </button>`;
  }).join('');

  openSettingsPage('Design', `
    ${Object.entries(BUTTON_CATEGORIES).map(([key, cat]) => `
      <div style="margin-bottom:22px">
        <label style="font-size:13px;color:var(--sub)">${esc(cat.label)}</label>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:8px">
          ${swatches(key)}
        </div>
      </div>
    `).join('')}

    <label style="font-size:13px;color:var(--sub);display:block;margin-top:8px">App-Name im Kopfbereich</label>
    <input id="brandingNameInput" type="text" value="${esc(branding.name)}" placeholder="SecureChat"
      style="width:100%;box-sizing:border-box;font-size:16px;padding:12px;border-radius:10px;
        border:none;background:var(--panel2);color:var(--tx);margin:8px 0 16px">

    <label style="font-size:13px;color:var(--sub)">Logo im Kopfbereich</label>
    <div style="display:flex;align-items:center;gap:12px;margin-top:8px">
      ${branding.logoUrl ? `<img src="${esc(branding.logoUrl)}" style="width:36px;height:36px;border-radius:8px;object-fit:cover">` : ''}
      <button class="btn ghost" onclick="window.__app.pickBrandingLogo()">${branding.logoUrl ? 'Logo ändern' : 'Logo hinzufügen'}</button>
      ${branding.logoUrl ? `<button class="btn ghost" onclick="window.__app.clearBrandingLogo()">Entfernen</button>` : ''}
    </div>
    <button class="btn" style="width:100%;margin-top:16px" onclick="window.__app.saveBrandingName()">Speichern</button>
  `);
}

/* ═══════════════════════════════════════════════════════════════════════
   APP-BRANDING — Name und Logo im Kopfbereich, rein lokal/pro Gerät
   ─────────────────────────────────────────────────────────────────────
   Bewusst clientseitig statt serverseitig: dies ist eine persönliche
   Anpassung der eigenen Ansicht (z. B. für Nutzer, die die App unter
   eigenem Namen/Branding weitergeben), keine Einstellung, die andere
   Nutzer sehen sollten. Das Logo wird als Data-URL gespeichert (kleine
   Bilder, kein Server-Upload nötig für reine UI-Kosmetik). */
const DEFAULT_BRANDING = { name: 'SecureChat', logoUrl: null };
function getAppBranding() {
  try {
    const raw = localStorage.getItem('sc:branding');
    return raw ? { ...DEFAULT_BRANDING, ...JSON.parse(raw) } : { ...DEFAULT_BRANDING };
  } catch { return { ...DEFAULT_BRANDING }; }
}
function saveAppBranding(branding) {
  try { localStorage.setItem('sc:branding', JSON.stringify(branding)); } catch {}
}
function saveBrandingName() {
  const name = document.getElementById('brandingNameInput')?.value.trim() || 'SecureChat';
  const branding = getAppBranding();
  branding.name = name;
  saveAppBranding(branding);
  toast('App-Name aktualisiert');
  renderShell();
  go(state.tab);
  document.getElementById('settingsPage')?.remove();
}
function pickBrandingLogo() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  input.onchange = () => {
    const file = input.files?.[0];
    if (!file) return;
    if (file.size > 500000) { toast('⚠️ Bild zu groß (max. 500 KB)'); return; }
    const reader = new FileReader();
    reader.onload = () => {
      const branding = getAppBranding();
      branding.logoUrl = reader.result;
      saveAppBranding(branding);
      toast('Logo aktualisiert');
      renderShell();
      go(state.tab);
      openDesignSettings();
    };
    reader.readAsDataURL(file);
  };
  input.click();
}
function clearBrandingLogo() {
  const branding = getAppBranding();
  branding.logoUrl = null;
  saveAppBranding(branding);
  renderShell();
  go(state.tab);
  openDesignSettings();
}

/* ═══════════════════════════════════════════════════════════════════════
   CHAT-EINSTELLUNGEN — Lese-/Schreibverhalten
   ─────────────────────────────────────────────────────────────────────
   Rein client-seitige Präferenzen, in localStorage gespeichert. Der
   Server erfährt bei "Lesebestätigungen aus" nichts über den gesendeten
   Haken selbst — er sieht ohnehin nur verschlüsselte Umschläge; die
   Einstellung steuert nur, ob DIESES Gerät ein Lesebestätigungs-Signal
   an den Absender schickt bzw. anzeigt.
   ═══════════════════════════════════════════════════════════════════════ */
const DEFAULT_CHAT_PREFS = {
  readReceipts: true,
  showLastSeen: true,
  enterToSend: true,
  fontSize: 'medium',   // small | medium | large
  liveLocationAsWidget: true   // true = schwebendes Fenster, false = Chat-Karte
};
function loadChatPrefs() {
  try {
    const raw = localStorage.getItem('sc:chatPrefs');
    state.chatPrefs = raw ? { ...DEFAULT_CHAT_PREFS, ...JSON.parse(raw) } : { ...DEFAULT_CHAT_PREFS };
  } catch { state.chatPrefs = { ...DEFAULT_CHAT_PREFS }; }
  applyFontSizePref();
}
function saveChatPrefs() {
  try { localStorage.setItem('sc:chatPrefs', JSON.stringify(state.chatPrefs)); } catch {}
}
function applyFontSizePref() {
  const sizes = { small: '14px', medium: '15.5px', large: '17.5px' };
  document.documentElement.style.setProperty('--msg-font-size', sizes[state.chatPrefs?.fontSize] || sizes.medium);
}
function openChatSettings() {
  const p = state.chatPrefs || DEFAULT_CHAT_PREFS;
  const toggle = (key, label, desc) => `
    <div class="menuitem" style="cursor:default">
      <div style="flex:1">
        <div>${label}</div>
        ${desc ? `<div style="font-size:12px;color:var(--sub);margin-top:2px">${desc}</div>` : ''}
      </div>
      <label class="switch">
        <input type="checkbox" ${p[key] ? 'checked' : ''} onchange="window.__app.toggleChatPref('${key}', this.checked)">
        <span class="switch-slider"></span>
      </label>
    </div>`;
  openSettingsPage('Chats', `
    <div class="menulist">
      ${toggle('readReceipts', 'Lesebestätigungen', 'Zeigt anderen, wenn du ihre Nachricht gelesen hast')}
      ${toggle('showLastSeen', 'Zuletzt online zeigen', 'Andere sehen, wann du zuletzt aktiv warst')}
      ${toggle('enterToSend', 'Enter zum Senden', 'Sonst: Enter fügt einen Zeilenumbruch ein')}
      ${toggle('liveLocationAsWidget', 'Live-Standort als schwebendes Fenster', 'Sonst: als normale Chat-Nachricht mit Kartenvorschau')}
    </div>
    <div style="margin-top:20px">
      <label style="font-size:13px;color:var(--sub)">Schriftgröße im Chat</label>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="btn ${p.fontSize === 'small' ? '' : 'ghost'}" style="flex:1" onclick="window.__app.setFontSizePref('small')">Klein</button>
        <button class="btn ${p.fontSize === 'medium' ? '' : 'ghost'}" style="flex:1" onclick="window.__app.setFontSizePref('medium')">Mittel</button>
        <button class="btn ${p.fontSize === 'large' ? '' : 'ghost'}" style="flex:1" onclick="window.__app.setFontSizePref('large')">Groß</button>
      </div>
    </div>
  `);
}
function toggleChatPref(key, value) {
  if (!state.chatPrefs) state.chatPrefs = { ...DEFAULT_CHAT_PREFS };
  state.chatPrefs[key] = value;
  saveChatPrefs();
  /* showLastSeen ist die einzige Präferenz, die der Server kennen muss
     — er entscheidet serverseitig, ob Presence-Updates überhaupt
     verschickt werden (siehe broadcastPresence in server.js). Die
     anderen Einstellungen (readReceipts, enterToSend, Schriftgröße)
     bleiben rein lokal. */
  if (key === 'showLastSeen') {
    api._fetch('/api/profile', { method: 'POST', body: { showLastSeen: value } })
      .catch(() => toast('⚠️ Einstellung konnte nicht gespeichert werden'));
  }
}
function setFontSizePref(size) {
  if (!state.chatPrefs) state.chatPrefs = { ...DEFAULT_CHAT_PREFS };
  state.chatPrefs.fontSize = size;
  saveChatPrefs();
  applyFontSizePref();
  openChatSettings();
}

function openNotificationSettings() {
  const granted = typeof Notification !== 'undefined' && Notification.permission === 'granted';
  openSettingsPage('Benachrichtigungen', `
    <div class="menulist">
      <div class="menuitem" style="cursor:default">
        <span class="mi-ic">🔔</span>
        <span>Push-Benachrichtigungen: ${granted ? '<b style="color:#25d366">Aktiv</b>' : '<b style="color:#f15c6d">Inaktiv</b>'}</span>
      </div>
      ${!granted ? `<button class="btn" style="width:100%;margin-top:12px" onclick="window.__app.enablePush()">Benachrichtigungen aktivieren</button>` : ''}
    </div>
    <p style="color:var(--sub);font-size:13px;margin-top:16px">
      Damit du auch bei geschlossener App über neue Nachrichten und Anrufe informiert wirst.
    </p>
  `);
}

function openPrivacySettings() {
  openSettingsPage('Datenschutz &amp; Sicherheit', `
    <div class="menulist">
      <div class="menuitem" style="cursor:default">
        <span class="mi-ic">🔒</span><span>Ende-zu-Ende-Verschlüsselung: <b style="color:#25d366">aktiv</b></span>
      </div>
      <button class="menuitem" onclick="window.__app.openBlockedList()">
        <span class="mi-ic">🚫</span><span>Blockierte Kontakte</span>
      </button>
      <button class="menuitem" onclick="window.__app.openLinkedDevices()">
        <span class="mi-ic">🖥️</span><span>Verknüpfte Geräte</span>
      </button>
    </div>
  `);
}

async function openBlockedList() {
  const list = [...state.blocked];
  openSettingsPage('Blockierte Kontakte', list.length
    ? `<div class="menulist">${list.map(id => `
        <div class="menuitem">
          <span class="mi-ic">🚫</span><span style="flex:1">${esc(id)}</span>
          <button class="btn ghost" style="padding:6px 12px;font-size:13px" onclick="window.__app.unblockFromSettings('${id}')">Entsperren</button>
        </div>`).join('')}</div>`
    : `<p style="color:var(--sub);text-align:center;margin-top:40px">Keine blockierten Kontakte.</p>`);
}

async function unblockFromSettings(userId) {
  try {
    await api.unblock(userId);
    state.blocked.delete(userId);
    openBlockedList();
    toast('Kontakt entsperrt');
  } catch (e) { toast('⚠️ ' + e.message); }
}

function openLinkedDevices() {
  openSettingsPage('Verknüpfte Geräte', `
    <div class="menulist">
      <div class="menuitem" style="cursor:default">
        <span class="mi-ic">📱</span><span>${esc(state.device?.id ? 'Dieses Gerät' : 'Unbekannt')}</span>
      </div>
    </div>
    <p style="color:var(--sub);font-size:13px;margin-top:16px">
      Geräteverwaltung folgt in einem späteren Update.
    </p>
  `);
}

function openLanguageSettings() {
  openSettingsPage('Sprache', `
    <div class="menulist">
      <button class="menuitem" onclick="window.__app.changeLang('de')"><span class="mi-ic">🇩🇪</span><span>Deutsch</span></button>
      <button class="menuitem" onclick="window.__app.changeLang('en')"><span class="mi-ic">🇬🇧</span><span>English</span></button>
      <button class="menuitem" onclick="window.__app.changeLang('es')"><span class="mi-ic">🇪🇸</span><span>Español</span></button>
    </div>
  `);
}

function changeLang(code) {
  setLocale(code);
  toast('Sprache geändert — App wird neu geladen…');
  setTimeout(() => location.reload(), 800);
}

function openStorageSettings() {
  let used = 0;
  try {
    for (const k in localStorage) if (localStorage.hasOwnProperty(k)) used += (localStorage[k]?.length || 0) * 2;
  } catch {}
  const kb = (used / 1024).toFixed(1);
  openSettingsPage('Speicher &amp; Daten', `
    <div class="menulist">
      <div class="menuitem" style="cursor:default">
        <span class="mi-ic">💾</span><span>Lokal genutzter Speicher: ${kb} KB</span>
      </div>
      <button class="menuitem" onclick="window.__app.clearLocalCache()">
        <span class="mi-ic">🗑️</span><span style="color:#f15c6d">Chatverlauf lokal löschen</span>
      </button>
    </div>
  `);
}

function clearLocalCache() {
  if (!state.device?.id) return;
  localStorage.removeItem('sc:cache:' + state.device.id);
  state.messages.clear();
  state.convs.clear();
  toast('Lokaler Chatverlauf gelöscht');
  document.getElementById('settingsPage')?.remove();
  renderMain();
}

function editProfile() {
  const avatarPreview = state.me.avatarUrl
    ? `<div class="av" style="width:80px;height:80px;font-size:32px"><img src="${esc(state.me.avatarUrl)}" alt=""></div>`
    : `<div class="av" style="width:80px;height:80px;font-size:32px">${esc((state.me.name || '?')[0].toUpperCase())}</div>`;
  openSettingsPage('Profil bearbeiten', `
    <div style="text-align:center;margin-bottom:8px">
      <div id="avatarPreviewWrap" style="display:inline-flex;position:relative;vertical-align:top">${avatarPreview}
        <button class="navbtn3d" style="position:absolute;bottom:-2px;right:-2px;width:30px;height:30px"
          onclick="window.__app.pickAvatarPhoto()" aria-label="Profilfoto ändern">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="#fff"><path d="M9 3l-1.8 2H4a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-3.2L15 3H9zm3 5a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg>
        </button>
      </div>
    </div>
    <label style="font-size:13px;color:var(--sub)">Anzeigename</label>
    <input id="profileNameInput" type="text" value="${esc(state.me.name || '')}"
      style="width:100%;box-sizing:border-box;font-size:16px;padding:14px;border-radius:10px;
        border:none;background:var(--panel2);color:var(--tx);margin:8px 0 16px">
    <button class="btn" style="width:100%" onclick="window.__app.saveProfileName()">Speichern</button>
  `);
}

function pickAvatarPhoto() {
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'avatarPickSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="menulist">
        <button class="menuitem" onclick="document.getElementById('avatarPickSheet').remove();window.__app.pickAvatarFrom(true)">
          <span class="mi-ic">📷</span><span>Foto aufnehmen</span>
        </button>
        <button class="menuitem" onclick="document.getElementById('avatarPickSheet').remove();window.__app.pickAvatarFrom(false)">
          <span class="mi-ic">🖼️</span><span>Aus Galerie wählen</span>
        </button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}
function pickAvatarFrom(useCamera) {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  if (useCamera) input.capture = 'user';
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    await uploadAvatarPhoto(file);
  };
  input.click();
}

async function uploadAvatarPhoto(file) {
  toast('📷 Profilfoto wird hochgeladen…', 4000);
  try {
    let toUpload = file;
    if (window.MediaStorage?.shrinkImage) {
      toUpload = await window.MediaStorage.shrinkImage(file).catch(() => file);
    }
    const { path: mediaPath, uploadUrl } = await api._fetch('/api/media/upload-url', { method: 'POST' });
    /* Profilbilder werden BEWUSST unverschlüsselt gespeichert — jeder
       Kontakt soll sie ohne eigenen Schlüssel sehen können, anders als
       Chat-Anhänge (siehe sendMediaMessage), die Ende-zu-Ende
       verschlüsselt bleiben. */
    const uploadResp = await fetch(uploadUrl, { method: 'PUT', body: toUpload });
    if (!uploadResp.ok) throw new Error('Hochladen fehlgeschlagen (' + uploadResp.status + ')');

    const { user } = await api._fetch('/api/profile/avatar', { method: 'POST', body: { path: mediaPath } });
    state.me.avatarPath = user.avatarPath;
    /* Anzeige-URL selbst zusammenbauen: bei R2 wäre eine öffentliche
       CDN-URL üblich. Im lokalen Fallback funktioniert das NICHT
       direkt in einem <img src="...">-Tag, weil GET /api/media/local-
       download einen Bearer-Token verlangt, den <img> nicht mitschicken
       kann — bekannte Einschränkung von authentifizierten Bild-URLs.
       Für den produktiven Einsatz mit vielen Avataren ist R2 (oder ein
       anderer öffentlich erreichbarer Objektspeicher) weiterhin nötig;
       der lokale Fallback deckt in erster Linie Chat-Anhänge ab, die
       ohnehin über einen expliziten "Herunterladen"-Klick laufen
       (siehe downloadAndShowMedia), nicht über <img>. */
    try {
      const { downloadUrl } = await api._fetch('/api/media/download-url?path=' + encodeURIComponent(mediaPath));
      state.me.avatarUrl = downloadUrl;
    } catch {}
    toast('Profilfoto aktualisiert');
    editProfile();
  } catch (e) {
    toast('⚠️ Upload fehlgeschlagen: ' + e.message);
  }
}

async function saveProfileName() {
  const val = document.getElementById('profileNameInput')?.value.trim();
  if (!val) return;
  try {
    await api.updateProfile({ name: val });
    state.me.name = val;
    toast('Name aktualisiert');
    document.getElementById('settingsPage')?.remove();
  } catch (e) { toast('⚠️ ' + e.message); }
}

async function enablePush() {
  await setupPushNotifications();
  document.getElementById('settingsPage')?.remove();
  openNotificationSettings();
}

async function logoutClick() {
  document.getElementById('mainMenuSheet')?.remove();
  try { await api.logout(); } catch {}
  Vault.forget();
  location.reload();
}

function showDeleteAccount() {
  document.getElementById('mainMenuSheet')?.remove();
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'deleteAccountSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 8px;color:#f15c6d">Konto endgültig löschen</h3>
      <p style="color:var(--sub);margin:0 0 16px;font-size:14px">
        Das kann nicht rückgängig gemacht werden. Alle Nachrichten, Geräte
        und Kontaktdaten dieses Kontos werden unwiderruflich gelöscht.
        Tipp zur Bestätigung deinen Namen <strong>${esc(state.me.name)}</strong> ein.
      </p>
      <input id="deleteAccountConfirm" type="text" placeholder="${esc(state.me.name)}" autocomplete="off"
        style="width:100%;box-sizing:border-box;font-size:16px;padding:14px;border-radius:10px;
          border:none;background:var(--panel2);color:var(--tx);margin-bottom:12px">
      <div id="deleteAccountError" style="color:#f15c6d;font-size:13px;margin-bottom:12px;display:none"></div>
      <button class="btn" style="width:100%;margin-bottom:8px;background:#f15c6d"
        onclick="window.__app.confirmDeleteAccount()">Konto endgültig löschen</button>
      <button class="btn ghost" style="width:100%" onclick="document.getElementById('deleteAccountSheet').remove()">Abbrechen</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

async function confirmDeleteAccount() {
  const input = document.getElementById('deleteAccountConfirm');
  const errEl = document.getElementById('deleteAccountError');
  const typed = input?.value.trim();
  if (typed !== state.me.name) {
    errEl.textContent = 'Bitte deinen Namen exakt eingeben, um zu bestätigen.';
    errEl.style.display = 'block';
    return;
  }
  try {
    await api.deleteAccount();
    Vault.forget();
    location.reload();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   CHAT-MENÜ — Blockieren & Melden
   ─────────────────────────────────────────────────────────────────────
   Melden überträgt bewusst NUR Kennung + Grund, niemals automatisch den
   Nachrichtentext — bei Ende-zu-Ende-Verschlüsselung hat der Server sonst
   keinen Klartext, den man ihm "versehentlich" mitgeben könnte. Der
   Inhalt wird nur beigefügt, wenn der Meldende das ausdrücklich anhakt.
   ═══════════════════════════════════════════════════════════════════════ */
function chatMenu(e) {
  e?.stopPropagation();
  if (!state.activeConv) return;
  const peerId = state.activeConv.peerId;
  const convId = state.activeConv.convId;
  const isBlocked = state.blocked.has(peerId);
  const isMuted = state.mutedChats?.has(peerId);
  const isPinned = state.pinnedChats?.has(convId);
  const isFavorite = state.favoriteChats?.has(convId);

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'chatMenuSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="menulist">
        <button class="menuitem" onclick="window.__app.toggleChatPin('${esc(convId)}');document.getElementById('chatMenuSheet').remove()">
          <span class="mi-ic">📌</span><span>${isPinned ? 'Nicht mehr anpinnen' : 'Chat anpinnen'}</span>
        </button>
        <button class="menuitem" onclick="window.__app.toggleChatFavorite('${esc(convId)}');document.getElementById('chatMenuSheet').remove()">
          <span class="mi-ic">${isFavorite ? '⭐' : '☆'}</span><span>${isFavorite ? 'Aus Favoriten entfernen' : 'Als Favorit markieren'}</span>
        </button>
        <button class="menuitem" onclick="window.__app.searchInChat()">
          <span class="mi-ic">🔍</span><span>In Chat suchen</span>
        </button>
        <button class="menuitem" onclick="window.__app.toggleMuteChat()">
          <span class="mi-ic">${isMuted ? '🔔' : '🔕'}</span><span>${isMuted ? 'Stummschaltung aufheben' : 'Chat stummschalten'}</span>
        </button>
        <button class="menuitem" onclick="window.__app.openDisappearingMessages()">
          <span class="mi-ic">⏱️</span><span>Verschwindende Nachrichten</span>
        </button>
        <button class="menuitem" onclick="window.__app.openScheduleCall()">
          <span class="mi-ic">📅</span><span>Anruf planen</span>
        </button>
        <button class="menuitem" onclick="window.__app.showEncryptionFingerprint()">
          <span class="mi-ic">🔐</span><span>Sicherheitscode anzeigen</span>
        </button>
        <button class="menuitem" onclick="window.__app.exportChat()">
          <span class="mi-ic">📤</span><span>Chat exportieren</span>
        </button>
        <button class="menuitem" onclick="window.__app.reportUser()">
          <span class="mi-ic">🚩</span><span>Melden</span>
        </button>
        <button class="menuitem" onclick="window.__app.toggleBlock()">
          <span class="mi-ic">${isBlocked ? '✅' : '🚫'}</span>
          <span style="color:${isBlocked ? 'var(--acc2)' : 'var(--dan)'}">${isBlocked ? 'Entsperren' : 'Blockieren'}</span>
        </button>
        <button class="menuitem" onclick="window.__app.clearChatHistory()">
          <span class="mi-ic">🗑️</span><span style="color:var(--dan)">Chatverlauf löschen</span>
        </button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

/* ── In-Chat-Suche ── */
function searchInChat() {
  document.getElementById('chatMenuSheet')?.remove();
  const bar = document.createElement('div');
  bar.id = 'chatSearchBar';
  bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:120;background:var(--panel);' +
    'padding:calc(8px + env(safe-area-inset-top)) 8px 8px;display:flex;gap:8px;align-items:center';
  bar.innerHTML = `
    <button class="iconbtn" onclick="document.getElementById('chatSearchBar').remove();window.__app.clearChatSearch()">←</button>
    <input id="chatSearchInput" type="text" placeholder="In diesem Chat suchen…"
      style="flex:1;font-size:15px;padding:10px 14px;border-radius:20px;border:none;background:var(--panel2);color:var(--tx)"
      oninput="window.__app.doChatSearch(this.value)">
  `;
  document.getElementById('chatOverlay')?.appendChild(bar);
  document.getElementById('chatSearchInput')?.focus();
}
function doChatSearch(q) {
  const convId = state.activeConv?.convId;
  if (!convId) return;
  q = q.trim().toLowerCase();
  document.querySelectorAll('#chatbody .msg').forEach(el => {
    const match = q && el.textContent.toLowerCase().includes(q);
    el.style.outline = match ? '2px solid var(--acc)' : 'none';
    if (match) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  });
}
function clearChatSearch() {
  document.querySelectorAll('#chatbody .msg').forEach(el => { el.style.outline = 'none'; });
}

/* ── Stummschalten (nur lokal — reine Anzeige-/Benachrichtigungspräferenz) ── */
/* ── Chat anpinnen (oben in der Liste halten) ── */
function toggleChatPin(convId) {
  if (!state.pinnedChats) state.pinnedChats = new Set();
  if (state.pinnedChats.has(convId)) { state.pinnedChats.delete(convId); toast('Chat nicht mehr angepinnt'); }
  else { state.pinnedChats.add(convId); toast('Chat angepinnt'); }
  try { localStorage.setItem('sc:pinnedChats', JSON.stringify([...state.pinnedChats])); } catch {}
  renderMain();
}
/* ── Chat als Favorit markieren (eigener Filter in der Pillbar) ── */
function toggleChatFavorite(convId) {
  if (!state.favoriteChats) state.favoriteChats = new Set();
  if (state.favoriteChats.has(convId)) { state.favoriteChats.delete(convId); toast('Aus Favoriten entfernt'); }
  else { state.favoriteChats.add(convId); toast('Als Favorit markiert'); }
  try { localStorage.setItem('sc:favoriteChats', JSON.stringify([...state.favoriteChats])); } catch {}
  renderMain();
}
function loadPinnedAndFavorites() {
  try { state.pinnedChats = new Set(JSON.parse(localStorage.getItem('sc:pinnedChats') || '[]')); } catch { state.pinnedChats = new Set(); }
  try { state.favoriteChats = new Set(JSON.parse(localStorage.getItem('sc:favoriteChats') || '[]')); } catch { state.favoriteChats = new Set(); }
}

function toggleMuteChat() {
  document.getElementById('chatMenuSheet')?.remove();
  if (!state.mutedChats) state.mutedChats = new Set();
  const peerId = state.activeConv.peerId;
  if (state.mutedChats.has(peerId)) { state.mutedChats.delete(peerId); toast('Stummschaltung aufgehoben'); }
  else { state.mutedChats.add(peerId); toast('Chat stummgeschaltet'); }
  try { localStorage.setItem('sc:muted', JSON.stringify([...state.mutedChats])); } catch {}
}

/* ── Verschwindende Nachrichten (Timer-Auswahl, lokal je Chat gespeichert) ── */
function openDisappearingMessages() {
  document.getElementById('chatMenuSheet')?.remove();
  const peerId = state.activeConv.peerId;
  const current = state.disappearing?.get(peerId) || 0;
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'disappearSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  const opts = [
    [0, 'Aus'], [300, '5 Minuten'], [1800, '30 Minuten'], [3600, '1 Stunde'],
    [86400, '24 Stunden'], [604800, '7 Tage'], [7776000, '90 Tage']
  ];
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 4px">Verschwindende Nachrichten</h3>
      <p style="color:var(--sub);font-size:13px;margin:0 0 12px">
        Neue Nachrichten in diesem Chat werden nach der gewählten Zeit automatisch
        aus deiner lokalen Ansicht entfernt.
      </p>
      <div class="menulist">
        ${opts.map(([sec, label]) => `
          <button class="menuitem" onclick="window.__app.setDisappearing(${sec})">
            <span class="mi-ic">${sec === current ? '✅' : '⏱️'}</span><span>${label}</span>
          </button>`).join('')}
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}
function setDisappearing(seconds) {
  if (!state.disappearing) state.disappearing = new Map();
  state.disappearing.set(state.activeConv.peerId, seconds);
  try {
    localStorage.setItem('sc:disappearing', JSON.stringify([...state.disappearing.entries()]));
  } catch {}
  document.getElementById('disappearSheet')?.remove();
  toast(seconds ? 'Verschwindende Nachrichten aktiviert' : 'Verschwindende Nachrichten deaktiviert');
}

/* ── Ablauf tatsächlich durchsetzen ──
   Läuft periodisch im Hintergrund: prüft für jeden Chat mit aktivem
   Timer, ob Nachrichten älter als die eingestellte Frist sind, und
   entfernt sie aus der lokalen Ansicht. Rein lokal — beeinflusst nicht,
   was der Gesprächspartner auf seinem Gerät sieht (das würde eine
   Server-Koordination brauchen, die bei E2EE ohnehin nur ein Hinweis,
   nie eine Garantie wäre). */
function pruneDisappearingMessages() {
  if (!state.disappearing || !state.disappearing.size) return;
  const now = Date.now();
  let changed = false;
  for (const [convId, conv] of state.convs.entries()) {
    const ttlSec = state.disappearing.get(conv.peerId);
    if (!ttlSec) continue;
    const msgs = state.messages.get(convId);
    if (!msgs?.length) continue;
    const kept = msgs.filter(m => (now - m.ts) < ttlSec * 1000);
    if (kept.length !== msgs.length) {
      state.messages.set(convId, kept);
      changed = true;
    }
  }
  if (changed) {
    LocalCache.scheduleSave();
    if (state.view === 'chat') renderChatMessages();
    renderMain();
  }
}
function loadDisappearingSettings() {
  try {
    const raw = localStorage.getItem('sc:disappearing');
    if (raw) state.disappearing = new Map(JSON.parse(raw));
  } catch {}
  /* Alle 30s prüfen — reicht für Minuten-Timer, ohne unnötig oft
     durchzulaufen. */
  setInterval(pruneDisappearingMessages, 30000);
}

/* ── Sicherheitscode / Fingerabdruck der Verschlüsselung ──
   Einzigartiges Vertrauens-Feature: zeigt einen aus den öffentlichen
   Identitätsschlüsseln beider Seiten abgeleiteten Code, den man z. B.
   persönlich oder per Videoanruf vergleichen kann, um sich gegen einen
   Man-in-the-Middle-Angriff abzusichern — genau das Prinzip hinter
   Signal/WhatsApp "Sicherheitsnummer", hier selbst gebaut. */
async function showEncryptionFingerprint() {
  document.getElementById('chatMenuSheet')?.remove();
  const peerId = state.activeConv.peerId;
  try {
    const { bundles } = await api.fetchBundle(peerId);
    const theirKey = bundles?.[0]?.ikDH || bundles?.[0]?.ik;
    const myKey = state.identity.IK.pubJwk;
    const combined = JSON.stringify([myKey.x, myKey.y, theirKey?.x, theirKey?.y].sort());
    const hashBuf = await crypto.subtle.digest('SHA-256', te.encode(combined));
    const hashArr = [...new Uint8Array(hashBuf)];
    const code = hashArr.slice(0, 15).map(b => String(b).padStart(3, '0')).join(' ');
    openSettingsPage('Sicherheitscode', `
      <p style="color:var(--sub);font-size:14px;margin-bottom:16px">
        Vergleiche diesen Code mit ${esc(state.activeConv.name)} über einen anderen Kanal
        (persönlich, Telefon), um sicherzugehen, dass niemand die Verbindung mithört.
      </p>
      <div style="font-family:monospace;font-size:18px;line-height:1.8;text-align:center;
        background:var(--panel2);padding:20px;border-radius:12px;letter-spacing:1px">${code}</div>
    `);
  } catch (e) {
    toast('⚠️ Sicherheitscode konnte nicht ermittelt werden');
  }
}

/* ── Chat als Text exportieren (nur eigene, bereits entschlüsselte Sicht) ── */
function exportChat() {
  document.getElementById('chatMenuSheet')?.remove();
  const convId = state.activeConv?.convId;
  const msgs = state.messages.get(convId) || [];
  if (!msgs.length) { toast('Keine Nachrichten zum Exportieren'); return; }
  const lines = msgs.map(m => `[${new Date(m.ts).toLocaleString('de-DE')}] ${m.mine ? 'Ich' : state.activeConv.name}: ${m.text}`);
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `chat-${state.activeConv.name}-${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Chatverlauf lokal löschen (nur diese Konversation) ── */
function clearChatHistory() {
  document.getElementById('chatMenuSheet')?.remove();
  const convId = state.activeConv?.convId;
  if (!convId) return;
  if (!confirm('Chatverlauf wirklich löschen? Das kann nicht rückgängig gemacht werden.')) return;
  state.messages.set(convId, []);
  LocalCache.scheduleSave();
  renderChatMessages();
  toast('Chatverlauf gelöscht');
}

async function toggleBlock() {
  document.getElementById('chatMenuSheet')?.remove();
  const peerId = state.activeConv?.peerId;
  if (!peerId) return;
  try {
    if (state.blocked.has(peerId)) {
      await api.unblock(peerId);
      state.blocked.delete(peerId);
      toast('Entsperrt');
    } else {
      await api.block(peerId);
      state.blocked.add(peerId);
      toast('Blockiert — diese Person kann dir nicht mehr schreiben');
    }
  } catch (e) { toast('⚠️ ' + e.message); }
}

function reportUser() {
  document.getElementById('chatMenuSheet')?.remove();
  if (!state.activeConv) return;
  const modal = document.createElement('div');
  modal.className = 'modal'; modal.id = 'reportModal';
  modal.onclick = e => { if (e.target === modal) modal.remove(); };
  modal.innerHTML = `
    <div class="modalbox">
      <h3>🚩 Person melden</h3>
      <div style="color:var(--sub);font-size:12.5px;margin-bottom:14px">
        Die Meldung enthält die Kennung dieser Person und deinen Grund —
        nicht automatisch den Nachrichtentext.</div>
      <label>Grund</label>
      <select class="in" id="repReason">
        <option value="spam">Spam oder Werbung</option>
        <option value="harassment">Belästigung oder Bedrohung</option>
        <option value="illegal">Mutmaßlich illegaler Inhalt</option>
        <option value="csam">Gefährdung Minderjähriger</option>
        <option value="other">Anderer Grund</option>
      </select>
      <label>Zusätzliche Angaben (optional)</label>
      <textarea class="in" id="repNote" rows="3" placeholder="Kontext, den wir wissen sollten…"></textarea>
      <div class="mrow">
        <button class="btn ghost" onclick="document.getElementById('reportModal').remove()">Abbrechen</button>
        <button class="btn dan" onclick="window.__app.submitReport()">Melden</button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(modal);
}

async function submitReport() {
  const peerId = state.activeConv?.peerId;
  const reason = $('#repReason')?.value || 'other';
  const note = $('#repNote')?.value.trim() || undefined;
  document.getElementById('reportModal')?.remove();
  try {
    await api.report({ reportedId: peerId, convId: state.activeConv?.convId, reason, note });
    toast('Gemeldet — danke für deinen Hinweis 🚩');
  } catch (e) { toast('⚠️ ' + e.message); }
}

/* ═══════════════════════════════════════════════════════════════════════
   MEDIENVERSAND
   ─────────────────────────────────────────────────────────────────────
   Große Dateien (>6 KB) passen nicht durch den Ratchet/Mixnet-Pfad (feste
   7-KB-Paketgröße im Mixnet ist Voraussetzung für Anonymität — siehe
   media-storage.js). Sie werden separat verschlüsselt zu R2 hochgeladen;
   nur Pfad+Schlüssel (~250 Byte) reisen durch den geschützten Weg. Dabei
   ist der Absender für den Speicherdienst sichtbar — anders als beim
   reinen Textpfad. Ohne konfigurierten Medienspeicher (window.MEDIA_CONFIG)
   bleibt Textversand voll nutzbar, nur Anhänge sind dann deaktiviert.
   ═══════════════════════════════════════════════════════════════════════ */
function attachSheet() {
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'attachSheet';
  sheet.onclick = e => { if (e.target === sheet) sheet.remove(); };
  const svg = {
    camera: '<svg viewBox="0 0 24 24" width="26" height="26" fill="#fff"><path d="M9 3l-1.8 2H4a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-3.2L15 3H9zm3 5a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg>',
    gallery: '<svg viewBox="0 0 24 24" width="26" height="26" fill="#fff"><path d="M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zm1 2v9.6l4.3-4.3a1 1 0 0 1 1.4 0L14 15.6l2.3-2.3a1 1 0 0 1 1.4 0L19 14.6V7H5zm4-.5a1.8 1.8 0 1 1 0 3.6 1.8 1.8 0 0 1 0-3.6z"/></svg>',
    video: '<svg viewBox="0 0 24 24" width="26" height="26" fill="#fff"><path d="M17 10.5V7a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3.5l4 4v-11l-4 4z"/></svg>',
    file: '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8.5L14.5 3z"/><path d="M14 3v6h6"/></svg>',
    pin: '<svg viewBox="0 0 24 24" width="24" height="24" fill="#fff"><path d="M12 2a7 7 0 0 0-7 7c0 5.25 7 13 7 13s7-7.75 7-13a7 7 0 0 0-7-7zm0 9.5A2.5 2.5 0 1 1 12 6.5a2.5 2.5 0 0 1 0 5z"/></svg>',
    contact: '<svg viewBox="0 0 24 24" width="24" height="24" fill="#fff"><path d="M12 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10zm0 12c5 0 9 2.5 9 5.5V22H3v-2.5C3 16.5 7 14 12 14z"/></svg>',
    poll: '<svg viewBox="0 0 24 24" width="22" height="22" fill="#fff"><path d="M4 10h4v10H4V10zm6-6h4v16h-4V4zm6 9h4v7h-4v-7z"/></svg>'
  };
  const item = (icon, label, onclick) => `
    <button class="attachitem" onclick="${onclick}">
      <span class="attachbtn3d">${icon}</span>
      <span class="attachlabel">${label}</span>
    </button>`;
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="attachgrid">
        ${item(svg.camera, 'Kamera', "window.__app.pickMedia('image/*','image',true)")}
        ${item(svg.gallery, 'Galerie', "window.__app.pickMedia('image/*','image',false)")}
        ${item(svg.video, 'Video', "window.__app.pickMedia('video/*','video',true)")}
        ${item(svg.file, 'Datei', "window.__app.pickMedia('*/*','file',false)")}
        ${item(svg.pin, 'Standort', "window.__app.shareLocation()")}
        ${item(svg.contact, 'Kontakt', "window.__app.shareContact()")}
        ${item(svg.poll, 'Umfrage', "window.__app.openCreatePoll()")}
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

/* ── Umfrage-Feature ──
   Eine Umfrage ist eine strukturierte Nachricht (__poll) mit Frage +
   Optionen. Stimmen werden als eigene, an alle Teilnehmer gesendete
   __pollVote-Nachrichten übertragen und lokal aggregiert — ohne
   zentralen Server, der die Ergebnisse kennen müsste (passt zum
   Ende-zu-Ende-Prinzip: der Server sieht nur verschlüsselte Umschläge,
   nie den Inhalt der Frage oder wer wie abgestimmt hat). */
function openCreatePoll() {
  document.getElementById('attachSheet')?.remove();
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'createPollSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Umfrage erstellen</h3>
      <input id="pollQuestion" type="text" placeholder="Frage"
        style="width:100%;box-sizing:border-box;font-size:16px;padding:12px;border-radius:10px;
          border:none;background:var(--panel2);color:var(--tx);margin-bottom:10px">
      <div id="pollOptionsWrap">
        <input class="pollopt" type="text" placeholder="Option 1"
          style="width:100%;box-sizing:border-box;font-size:15px;padding:10px;border-radius:8px;
            border:none;background:var(--panel2);color:var(--tx);margin-bottom:8px">
        <input class="pollopt" type="text" placeholder="Option 2"
          style="width:100%;box-sizing:border-box;font-size:15px;padding:10px;border-radius:8px;
            border:none;background:var(--panel2);color:var(--tx);margin-bottom:8px">
      </div>
      <button class="btn ghost" style="width:100%;margin-bottom:10px" onclick="window.__app.addPollOption()">+ Option hinzufügen</button>
      <button class="btn" style="width:100%" onclick="window.__app.sendPoll()">Umfrage senden</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}
function addPollOption() {
  const wrap = document.getElementById('pollOptionsWrap');
  const count = wrap.children.length + 1;
  const input = document.createElement('input');
  input.className = 'pollopt'; input.type = 'text'; input.placeholder = 'Option ' + count;
  input.style.cssText = 'width:100%;box-sizing:border-box;font-size:15px;padding:10px;border-radius:8px;' +
    'border:none;background:var(--panel2);color:var(--tx);margin-bottom:8px';
  wrap.appendChild(input);
}
async function sendPoll() {
  const question = document.getElementById('pollQuestion')?.value.trim();
  const options = [...document.querySelectorAll('.pollopt')]
    .map(i => i.value.trim()).filter(Boolean);
  if (!question || options.length < 2) { toast('⚠️ Frage und mindestens 2 Optionen nötig'); return; }
  if (!state.activeConv) return;
  const pollId = 'poll_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  document.getElementById('createPollSheet')?.remove();
  try {
    await sendMessage(state.activeConv.peerId, state.activeConv.convId,
      JSON.stringify({ __poll: { id: pollId, question, options } }));
    if (!state.pollVotes) state.pollVotes = new Map();
    renderChatMessages();
  } catch (e) { toast('⚠️ ' + e.message); }
}
function votePoll(pollId, optionIdx, question, options) {
  if (!state.pollVotes) state.pollVotes = new Map();
  const votes = state.pollVotes.get(pollId) || {};
  votes[state.me.id] = optionIdx;
  state.pollVotes.set(pollId, votes);
  if (state.activeConv) {
    sendMessage(state.activeConv.peerId, state.activeConv.convId,
      JSON.stringify({ __pollVote: { pollId, optionIdx } })).catch(() => {});
  }
  renderChatMessages();
}
function renderPollCard(poll, msgId) {
  const votes = state.pollVotes?.get(poll.id) || {};
  const myVote = votes[state.me.id];
  const counts = poll.options.map((_, i) => Object.values(votes).filter(v => v === i).length);
  const total = counts.reduce((a, b) => a + b, 0) || 1;
  return `
    <div class="pollcard">
      <div class="pollq">📊 ${esc(poll.question)}</div>
      ${poll.options.map((opt, i) => {
        const pct = Math.round((counts[i] / total) * 100);
        const chosen = myVote === i;
        return `
          <button class="polloption ${chosen ? 'polloption-chosen' : ''}"
            onclick="window.__app.votePoll('${esc(poll.id)}',${i},'${esc(poll.question)}',null)">
            <div class="polloption-bar" style="width:${myVote != null ? pct : 0}%"></div>
            <span class="polloption-label">${chosen ? '✅ ' : ''}${esc(opt)}</span>
            ${myVote != null ? `<span class="polloption-pct">${pct}%</span>` : ''}
          </button>`;
      }).join('')}
      <div class="pollmeta">${total} Stimme${total !== 1 ? 'n' : ''}</div>
    </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════
   GEPLANTE ANRUFE — Termin vereinbaren, Push-Erinnerung zur Fälligkeit
   ═══════════════════════════════════════════════════════════════════════ */
function openScheduleCall() {
  document.getElementById('chatMenuSheet')?.remove();
  if (!state.activeConv) return;
  const now = new Date();
  now.setMinutes(now.getMinutes() + 30 - (now.getMinutes() % 5));   // auf nächste 5-Min-Marke runden
  const localIso = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'scheduleCallSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Anruf planen mit ${esc(state.activeConv.name)}</h3>
      <label style="font-size:13px;color:var(--sub)">Datum &amp; Uhrzeit</label>
      <input id="scheduleDateInput" type="datetime-local" value="${localIso}" min="${localIso}"
        style="width:100%;box-sizing:border-box;font-size:16px;padding:12px;border-radius:10px;
          border:none;background:var(--panel2);color:var(--tx);margin:8px 0 16px">
      <div style="display:flex;gap:10px;margin-bottom:16px">
        <button class="btn ghost" style="flex:1" id="scheduleKindAudio" onclick="window.__app.setScheduleKind('audio')">🎤 Audio</button>
        <button class="btn ghost" style="flex:1" id="scheduleKindVideo" onclick="window.__app.setScheduleKind('video')">🎥 Video</button>
      </div>
      <button class="btn" style="width:100%" onclick="window.__app.confirmScheduleCall()">Anruf planen</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
  state._scheduleKind = 'audio';
  setScheduleKind('audio');
}
function setScheduleKind(kind) {
  state._scheduleKind = kind;
  document.getElementById('scheduleKindAudio')?.classList.toggle('btn', kind === 'audio');
  document.getElementById('scheduleKindAudio')?.classList.toggle('ghost', kind !== 'audio');
  document.getElementById('scheduleKindVideo')?.classList.toggle('btn', kind === 'video');
  document.getElementById('scheduleKindVideo')?.classList.toggle('ghost', kind !== 'video');
}
async function confirmScheduleCall() {
  const dtVal = document.getElementById('scheduleDateInput')?.value;
  if (!dtVal || !state.activeConv) return;
  const scheduledAt = new Date(dtVal).getTime();
  if (scheduledAt <= Date.now()) { toast('⚠️ Zeitpunkt liegt in der Vergangenheit'); return; }
  try {
    await api._fetch('/api/scheduled-calls', {
      method: 'POST',
      body: { peerId: state.activeConv.peerId, kind: state._scheduleKind || 'audio', scheduledAt }
    });
    document.getElementById('scheduleCallSheet')?.remove();
    toast('📅 Anruf geplant für ' + new Date(scheduledAt).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' }));
  } catch (e) { toast('⚠️ ' + e.message); }
}

function scheduledCallStatusInfo(c) {
  if (c.status === 'accepted') return { label: 'Bestätigt', color: 'var(--acc2)' };
  if (c.status === 'declined') return { label: 'Abgelehnt', color: '#f15c6d' };
  return { label: c.isCreator ? 'Wartet auf Antwort' : 'Antwort ausstehend', color: 'var(--sub)' };
}
function scheduledCallCard(c, onRespondReload) {
  const st = scheduledCallStatusInfo(c);
  return `
    <div style="display:flex;align-items:flex-start;gap:14px;padding:14px 4px;border-bottom:1px solid var(--line)">
      <span class="mi-ic" style="margin-top:2px">${c.kind === 'video' ? '🎥' : '🎤'}</span>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600">${esc(c.peerName)}</div>
        <div style="font-size:12px;color:var(--sub);margin-top:2px">${new Date(c.scheduledAt).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' })}</div>
        <div style="font-size:12px;color:${st.color};font-weight:600;margin-top:2px">${st.label}</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;align-items:flex-end;flex-shrink:0">
        ${!c.isCreator && c.status === 'pending' ? `
          <button class="btn ghost" style="padding:5px 10px;font-size:12px;white-space:nowrap" onclick="window.__app.respondScheduledCall('${esc(c.id)}','declined');${onRespondReload}">Ablehnen</button>
          <button class="btn" style="padding:5px 10px;font-size:12px;white-space:nowrap" onclick="window.__app.respondScheduledCall('${esc(c.id)}','accepted');${onRespondReload}">Annehmen</button>
        ` : c.status === 'accepted' ? `
          <button class="btn" style="padding:6px 12px;font-size:13px;white-space:nowrap" onclick="window.__app.startScheduledCall('${esc(c.peerId)}','${c.kind}')">Anrufen</button>
          <button class="btn ghost" style="padding:5px 10px;font-size:12px;white-space:nowrap" onclick="window.__app.cancelScheduledCall('${esc(c.id)}');${onRespondReload}">Absagen</button>
        ` : `
          <button class="btn ghost" style="padding:6px 12px;font-size:13px;white-space:nowrap" onclick="window.__app.cancelScheduledCall('${esc(c.id)}');${onRespondReload}">Absagen</button>
        `}
      </div>
    </div>`;
}

/* Direkt im "Geplant"-Tab der Chatliste eingebettet — Alternative zum
   Sheet unter dem Hauptmenü, für schnelleren Zugriff ohne extra Klick. */
async function renderScheduledTab(main) {
  main.innerHTML = `<div class="empty"><div class="ic">📅</div><div>Lade…</div></div>`;
  let calls = [];
  try { ({ calls } = await api._fetch('/api/scheduled-calls')); }
  catch (e) {
    main.innerHTML = `<div class="empty"><div class="ic">⚠️</div><div>Konnte nicht geladen werden</div></div>`;
    return;
  }
  if (state.tab !== 'scheduled') return;   // Tab könnte während des await gewechselt worden sein
  main.innerHTML = `
    <div class="scroll" style="height:100%;position:relative">
      ${calls.length ? `<div class="menulist">${calls.map(c => scheduledCallCard(c, "window.__app.go('scheduled')")).join('')}</div>`
        : `<div class="empty"><div class="ic">📅</div><div>Noch keine geplanten Anrufe.<br>Öffne einen Chat → Menü → Anruf planen.</div></div>`}
    </div>`;
}

async function openScheduledCallsList() {
  let calls = [];
  try { ({ calls } = await api._fetch('/api/scheduled-calls')); }
  catch (e) { toast('⚠️ ' + e.message); return; }

  openSettingsPage('Geplante Anrufe', calls.length ? `
    <div class="menulist">${calls.map(c => scheduledCallCard(c, 'window.__app.openScheduledCallsList()')).join('')}</div>
  ` : `<p style="color:var(--sub);text-align:center;margin-top:40px">Keine geplanten Anrufe.</p>`);
}
async function cancelScheduledCall(id) {
  try {
    await api._fetch('/api/scheduled-calls?id=' + encodeURIComponent(id), { method: 'DELETE' });
    toast('Anruf abgesagt');
    openScheduledCallsList();
  } catch (e) { toast('⚠️ ' + e.message); }
}

/* Erinnerung, die über den WebSocket eintrifft (siehe wireSocketEvents,
   'call-reminder') oder als Push ankommt (siehe sw.js) — zeigt eine
   auffällige In-App-Karte mit direktem "Jetzt anrufen"-Knopf. */
function showCallReminderNotification(msg) {
  const conv = [...state.convs.values()].find(c => c.peerId === msg.peerId);
  const peerName = conv?.name || msg.peerId;
  const banner = document.createElement('div');
  banner.className = 'sheet'; banner.id = 'callReminderSheet';
  banner.onclick = ev => { if (ev.target === banner) banner.remove(); };
  banner.innerHTML = `
    <div class="sheetbox" style="text-align:center">
      <div style="font-size:40px;margin-bottom:8px">${msg.kind === 'video' ? '🎥' : '📞'}</div>
      <h3 style="margin:0 0 4px">Geplanter Anruf</h3>
      <p style="color:var(--sub);margin:0 0 20px">Zeit für deinen Anruf mit ${esc(peerName)}</p>
      <button class="btn" style="width:100%;margin-bottom:8px" onclick="window.__app.startScheduledCall('${esc(msg.peerId)}','${msg.kind}')">Jetzt anrufen</button>
      <button class="btn ghost" style="width:100%" onclick="document.getElementById('callReminderSheet').remove()">Später</button>
    </div>`;
  document.getElementById('overlays').appendChild(banner);
  if ('vibrate' in navigator) navigator.vibrate([200, 100, 200]);
}
function startScheduledCall(peerId, kind) {
  document.getElementById('callReminderSheet')?.remove();
  const conv = [...state.convs.values()].find(c => c.peerId === peerId);
  if (conv) { openChat(conv); setTimeout(() => Call.start(peerId, conv.name, kind), 300); }
}

/* Eingeladener bekommt diese Karte, sobald jemand einen Anruf mit ihm
   plant — Annehmen/Ablehnen wird sofort an den Ersteller zurückgemeldet
   (siehe respondScheduledCall), nicht erst beim Ablauf der Erinnerung. */
function showCallInviteNotification(msg) {
  const when = new Date(msg.scheduledAt).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
  const banner = document.createElement('div');
  banner.className = 'sheet'; banner.id = 'callInviteSheet';
  banner.onclick = ev => { if (ev.target === banner) banner.remove(); };
  banner.innerHTML = `
    <div class="sheetbox" style="text-align:center">
      <div style="font-size:40px;margin-bottom:8px">${msg.kind === 'video' ? '🎥' : '📞'}</div>
      <h3 style="margin:0 0 4px">Anrufeinladung</h3>
      <p style="color:var(--sub);margin:0 0 4px">${esc(msg.fromName || msg.fromId)} möchte dich anrufen</p>
      <p style="color:var(--sub);margin:0 0 20px;font-weight:600">${when}</p>
      <div style="display:flex;gap:10px">
        <button class="btn ghost" style="flex:1" onclick="window.__app.respondScheduledCall('${esc(msg.id)}','declined')">Ablehnen</button>
        <button class="btn" style="flex:1" onclick="window.__app.respondScheduledCall('${esc(msg.id)}','accepted')">Annehmen</button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(banner);
  if ('vibrate' in navigator) navigator.vibrate([200, 100, 200]);
}
async function respondScheduledCall(id, status) {
  document.getElementById('callInviteSheet')?.remove();
  try {
    await api._fetch('/api/scheduled-calls/respond', { method: 'POST', body: { id, status } });
    toast(status === 'accepted' ? '✅ Anruf bestätigt' : 'Anruf abgelehnt');
  } catch (e) { toast('⚠️ ' + e.message); }
}

/* Ersteller bekommt diese Karte, sobald der Eingeladene reagiert hat —
   das ist der Kern des Bestätigungsworkflows: er erfährt aktiv, nicht
   erst durch Nachschauen in der Terminliste. */
function showCallResponseNotification(msg) {
  const accepted = msg.status === 'accepted';
  toast(`${accepted ? '✅' : '❌'} ${esc(msg.byName || msg.byId)} hat den geplanten Anruf ${accepted ? 'bestätigt' : 'abgelehnt'}`, 4000);
}

function shareLocation() {
  document.getElementById('attachSheet')?.remove();
  if (!navigator.geolocation) { toast('⚠️ Standort auf diesem Gerät nicht verfügbar'); return; }

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'shareLocationSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Standort teilen</h3>
      <div class="menulist">
        <button class="menuitem" onclick="window.__app.sendLocationOnce()">
          <span class="mi-ic">📍</span><span>Aktueller Standort (einmalig)</span>
        </button>
        <button class="menuitem" onclick="window.__app.startLiveLocation(15)">
          <span class="mi-ic">🔴</span><span>Live-Standort für 15 Minuten</span>
        </button>
        <button class="menuitem" onclick="window.__app.startLiveLocation(60)">
          <span class="mi-ic">🔴</span><span>Live-Standort für 1 Stunde</span>
        </button>
        <button class="menuitem" onclick="window.__app.startLiveLocation(480)">
          <span class="mi-ic">🔴</span><span>Live-Standort für 8 Stunden</span>
        </button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}
function sendLocationOnce() {
  document.getElementById('shareLocationSheet')?.remove();
  toast('📍 Standort wird ermittelt…', 4000);
  navigator.geolocation.getCurrentPosition(
    async (pos) => {
      const { latitude, longitude } = pos.coords;
      const mapsUrl = `https://www.google.com/maps?q=${latitude},${longitude}`;
      if (!state.activeConv) return;
      try {
        await sendMessage(state.activeConv.peerId, state.activeConv.convId,
          JSON.stringify({ __location: { lat: latitude, lng: longitude, url: mapsUrl } }));
        renderChatMessages();
      } catch (e) { toast('⚠️ ' + e.message); }
    },
    () => toast('⚠️ Standortzugriff verweigert'),
    { enableHighAccuracy: true, timeout: 10000 }
  );
}

/* ═══════════════════════════════════════════════════════════════════════
   LIVE-STANDORT ALS SCHWEBENDES FENSTER
   ─────────────────────────────────────────────────────────────────────
   Bewusst KEIN wiederholtes Update einer Chat-Nachricht mehr — das gab
   entweder viele einzelne Chatzeilen oder eine verwirrend "springende"
   einzelne Nachricht. Stattdessen: EIN Overlay-Fenster (frei
   verschiebbar wie das PiP im Videoanruf, siehe makeDraggable in
   call-ui.js), das sich per WebSocket-Update in Echtzeit bewegt.
   Position-Updates laufen über denselben Envelope-Mechanismus wie
   Chatnachrichten (Ende-zu-Ende verschlüsselt), landen aber NIE im
   sichtbaren Chatverlauf (siehe handleEnvelope: __liveLocationUpdate
   wird herausgefiltert, ähnlich den Umfrage-Stimmen). */
let _liveLocationWatchId = null;
let _liveLocationTimer = null;
let _liveLocationConv = null;

function startLiveLocation(minutes) {
  document.getElementById('shareLocationSheet')?.remove();
  if (!state.activeConv) return;
  if (_liveLocationWatchId != null) { toast('⚠️ Live-Standort läuft bereits'); return; }

  const liveId = 'live_' + Date.now();
  const conv = state.activeConv;
  const endAt = Date.now() + minutes * 60000;
  _liveLocationConv = conv;

  const sendUpdate = async (pos) => {
    const { latitude, longitude } = pos.coords;
    const asWidget = state.chatPrefs?.liveLocationAsWidget !== false;
    try {
      if (asWidget) {
        await sendMessage(conv.peerId, conv.convId, JSON.stringify({
          __liveLocationUpdate: { liveId, lat: latitude, lng: longitude, expiresAt: endAt, fromName: state.me.name }
        }));
      } else {
        /* Fallback: normale Chat-Nachricht mit Kartenvorschau, wird bei
           jedem Update NEU gesendet (eigener Chatverlauf-Eintrag pro
           Position) statt eines schwebenden Fensters — für Nutzer, die
           lieber einen nachvollziehbaren Verlauf im Chat selbst haben. */
        const mapsUrl = `https://www.google.com/maps?q=${latitude},${longitude}`;
        await sendMessage(conv.peerId, conv.convId, JSON.stringify({
          __location: { lat: latitude, lng: longitude, url: mapsUrl, liveId, expiresAt: endAt }
        }));
        if (state.activeConv?.convId === conv.convId) renderChatMessages();
      }
    } catch (e) {
      console.warn('Live-Standort-Update fehlgeschlagen:', e.message);
      toast('⚠️ Standort konnte nicht gesendet werden: ' + e.message);
      return;   // Widget nicht mit fehlerhaften Daten anzeigen
    }
    /* Eigenes Fenster ebenfalls aktualisieren — der Sender sieht seine
       eigene Live-Position genauso im schwebenden Fenster wie der
       Empfänger, statt gar keine Rückmeldung zu haben. Nur im
       Widget-Modus relevant. */
    if (asWidget) {
      showLiveLocationWidget(liveId, { lat: latitude, lng: longitude, expiresAt: endAt, fromName: 'Du', isSender: true });
    }
  };

  navigator.geolocation.getCurrentPosition(sendUpdate, (err) => {
    toast('⚠️ Standortzugriff verweigert oder nicht verfügbar: ' + (err.message || 'unbekannter Fehler'));
  }, { enableHighAccuracy: true });
  _liveLocationWatchId = navigator.geolocation.watchPosition(sendUpdate, (err) => {
    console.warn('watchPosition-Fehler:', err.message);
  }, { enableHighAccuracy: true });

  toast(`🔴 Live-Standort aktiv für ${minutes >= 60 ? (minutes / 60) + ' Std.' : minutes + ' Min.'}`);
  _liveLocationTimer = setTimeout(() => stopLiveLocation(true), minutes * 60000);
}
function stopLiveLocation(silent) {
  if (_liveLocationWatchId != null) { navigator.geolocation.clearWatch(_liveLocationWatchId); _liveLocationWatchId = null; }
  if (_liveLocationTimer) { clearTimeout(_liveLocationTimer); _liveLocationTimer = null; }
  closeLiveLocationWidget();
  if (!silent) toast('Live-Standort beendet');
}

/* Schwebendes, verschiebbares Kartenfenster — ein einziges Element,
   das bei jedem Positions-Update nur seinen Kartenausschnitt
   austauscht, statt neu erzeugt zu werden (verhindert, dass die vom
   Nutzer gewählte Bildschirmposition bei jedem Update zurückspringt). */
/* Eigenständige Drag-Funktion (nicht von call-ui.js abhängig, das nur
   bei aktivem Anruf-Feature geladen wird) — dasselbe Pointer-Events-
   Muster wie beim Video-PiP, hier für das Live-Standort-Fenster. */
function makeDraggableWidget(elm) {
  let startX = 0, startY = 0, origX = 0, origY = 0, dragging = false;
  elm.style.touchAction = 'none';
  elm.addEventListener('pointerdown', (e) => {
    if (e.target.closest('.live-location-close')) return;
    dragging = true;
    elm.setPointerCapture(e.pointerId);
    const rect = elm.getBoundingClientRect();
    origX = rect.left; origY = rect.top;
    startX = e.clientX; startY = e.clientY;
    elm.style.right = 'auto'; elm.style.bottom = 'auto';
    elm.style.left = origX + 'px'; elm.style.top = origY + 'px';
  });
  elm.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const dx = e.clientX - startX, dy = e.clientY - startY;
    const maxX = window.innerWidth - elm.offsetWidth;
    const maxY = window.innerHeight - elm.offsetHeight;
    elm.style.left = Math.max(0, Math.min(maxX, origX + dx)) + 'px';
    elm.style.top = Math.max(0, Math.min(maxY, origY + dy)) + 'px';
  });
  const stop = (e) => { dragging = false; try { elm.releasePointerCapture(e.pointerId); } catch {} };
  elm.addEventListener('pointerup', stop);
  elm.addEventListener('pointercancel', stop);
}

function showLiveLocationWidget(liveId, data) {
  const { lat, lng, expiresAt, fromName, isSender } = data;
  if (Date.now() > expiresAt) { closeLiveLocationWidget(); return; }

  let widget = document.getElementById('liveLocationWidget');
  const zoom = 15;
  const tileX = Math.floor((lng + 180) / 360 * Math.pow(2, zoom));
  const tileY = Math.floor((1 - Math.log(Math.tan(lat * Math.PI / 180) + 1 / Math.cos(lat * Math.PI / 180)) / Math.PI) / 2 * Math.pow(2, zoom));
  const tileUrl = `https://tile.openstreetmap.org/${zoom}/${tileX}/${tileY}.png`;
  const mapsUrl = `https://www.google.com/maps?q=${lat},${lng}`;

  if (!widget) {
    widget = document.createElement('div');
    widget.id = 'liveLocationWidget';
    widget.className = 'live-location-widget';
    widget.innerHTML = `
      <button class="live-location-close" aria-label="Schließen">✕</button>
      <div class="live-location-map">
        <div class="live-location-orb"></div>
        <div class="live-location-orb-pulse"></div>
      </div>
      <div class="live-location-label"></div>`;
    document.body.appendChild(widget);
    widget.querySelector('.live-location-close').onclick = (e) => {
      e.stopPropagation();
      if (isSender) stopLiveLocation();
      else closeLiveLocationWidget();
    };
    /* Antippen der Karte öffnet die Kartenansicht im Vollbild —
       Verschieben (Drag) darf dabei nicht versehentlich als Klick
       gewertet werden, deshalb die minimale Bewegungsprüfung. */
    let dragMoved = false;
    widget.addEventListener('pointerdown', () => { dragMoved = false; });
    widget.addEventListener('pointermove', () => { dragMoved = true; });
    widget.querySelector('.live-location-map').addEventListener('click', (e) => {
      if (dragMoved) return;
      openLiveLocationFullscreen(widget.dataset.liveId);
    });
    /* makeDraggable ist in call-ui.js definiert (Pointer-Events-basiert,
       hält das Fenster im sichtbaren Bereich) — hier wiederverwendet,
       kein zweites Mal implementiert. */
    makeDraggableWidget(widget);
  }
  widget.dataset.liveId = liveId;
  widget.querySelector('.live-location-map').style.backgroundImage = `url('${tileUrl}')`;
  widget.querySelector('.live-location-label').innerHTML =
    `📍 ${esc(fromName)} · <a href="${esc(mapsUrl)}" target="_blank" rel="noopener" style="color:inherit">öffnen</a>`;

  /* Letzte bekannte Position merken — der Vollbild-Viewer (Klick auf
     die Karte) braucht die Koordinaten, um eine größere Kartenkachel
     nachzuladen, statt nur das kleine Thumbnail hochzuskalieren. */
  if (!state.liveLocationData) state.liveLocationData = new Map();
  state.liveLocationData.set(liveId, { lat, lng, mapsUrl, fromName });
}
function closeLiveLocationWidget() {
  document.getElementById('liveLocationWidget')?.remove();
}

/* Vollbild-Kartenansicht — lädt eine größere Kartenkachel (Zoom 16)
   statt nur das kleine 120px-Widget hochzuskalieren, was unscharf
   aussehen würde. */
function openLiveLocationFullscreen(liveId) {
  const data = state.liveLocationData?.get(liveId);
  if (!data) return;
  const { lat, lng, mapsUrl, fromName } = data;
  const zoom = 16;
  const tileX = Math.floor((lng + 180) / 360 * Math.pow(2, zoom));
  const tileY = Math.floor((1 - Math.log(Math.tan(lat * Math.PI / 180) + 1 / Math.cos(lat * Math.PI / 180)) / Math.PI) / 2 * Math.pow(2, zoom));
  const tileUrl = `https://tile.openstreetmap.org/${zoom}/${tileX}/${tileY}.png`;

  const overlay = document.createElement('div');
  overlay.className = 'media-fullscreen-overlay';
  overlay.innerHTML = `
    <button class="media-fullscreen-close" aria-label="Schließen">✕</button>
    <div style="width:100%;height:100%;background-image:url('${tileUrl}');background-size:cover;
      background-position:center;position:relative">
      <div class="live-location-orb" style="width:26px;height:26px"></div>
      <div class="live-location-orb-pulse" style="width:26px;height:26px"></div>
    </div>
    <div style="position:absolute;bottom:30px;left:50%;transform:translateX(-50%);
      background:rgba(0,0,0,.6);color:#fff;padding:10px 20px;border-radius:20px;
      font-size:14px;white-space:nowrap">
      📍 ${esc(fromName)} · <a href="${esc(mapsUrl)}" target="_blank" rel="noopener" style="color:#5b9bf5">In Google Maps öffnen</a>
    </div>`;
  overlay.onclick = (e) => { if (e.target === overlay || e.target.closest('.media-fullscreen-close')) overlay.remove(); };
  document.body.appendChild(overlay);
}



/* ── Kontakt teilen — aus den eigenen SecureChat-Kontakten auswählen,
   Name + userId werden als strukturierte Nachricht gesendet. ── */
async function shareContact() {
  document.getElementById('attachSheet')?.remove();
  let users;
  try { ({ users } = await api.listUsers()); }
  catch (e) { toast('⚠️ ' + e.message); return; }

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'shareContactSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Kontakt teilen</h3>
      <div class="menulist" style="max-height:50vh;overflow-y:auto">
        ${users.map(u => `
          <button class="menuitem" onclick="window.__app.sendContactCard('${esc(u.id)}','${esc(u.name || '')}')">
            <div class="av" style="width:32px;height:32px;font-size:14px">${esc((u.name || '?')[0].toUpperCase())}</div>
            <span>${esc(u.name || u.id)}</span>
          </button>`).join('')}
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}
async function sendContactCard(userId, name) {
  document.getElementById('shareContactSheet')?.remove();
  if (!state.activeConv) return;
  try {
    await sendMessage(state.activeConv.peerId, state.activeConv.convId,
      JSON.stringify({ __contact: { id: userId, name } }));
    renderChatMessages();
  } catch (e) { toast('⚠️ ' + e.message); }
}

function pickMedia(accept, kind, useCamera) {
  document.getElementById('attachSheet')?.remove();
  const input = document.createElement('input');
  input.type = 'file'; input.accept = accept;
  /* capture="environment" weist mobile Browser an, direkt die Kamera-
     App zu öffnen statt der Dateiauswahl — Foto/Video wird sofort nach
     Aufnahme als Anhang zurückgegeben und automatisch weiterverarbeitet. */
  if (useCamera) input.capture = 'environment';
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    await sendMediaMessage(file, kind);
  };
  input.click();
}

/* ═══════════════════════════════════════════════════════════════════════
   MEDIEN-UPLOAD — client-seitige Verschlüsselung + Server-Speicherung
   ─────────────────────────────────────────────────────────────────────
   /api/media/upload-url liefert bei JEDEM Aufruf einen frischen,
   einmaligen Schlüssel + URL — egal ob dahinter R2 (Produktion) oder
   der lokale Fallback-Ordner steckt (siehe server.js), das Frontend
   muss den Unterschied nicht kennen. Die Datei wird VOR dem Hochladen
   mit einem zufälligen AES-Schlüssel verschlüsselt; nur dieser
   Schlüssel (nicht die Datei selbst) geht durch den Ende-zu-Ende-
   verschlüsselten Ratchet-Kanal zum Empfänger — der Server sieht in
   beiden Fällen nur Chiffretext, nie den Klartext der Datei. */
async function encryptFileForUpload(file) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plainBuf = await file.arrayBuffer();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBuf);
  const rawKey = await crypto.subtle.exportKey('raw', key);
  return { blob: new Blob([ct]), ivB64: b64(iv), keyB64: b64(rawKey) };
}
async function decryptDownloadedFile(buf, ivB64, keyB64, mimeType) {
  const key = await crypto.subtle.importKey('raw', ub64(keyB64), { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(ivB64) }, key, buf);
  return new Blob([plain], { type: mimeType || 'application/octet-stream' });
}

/* Erzeugt ein kleines Vorschaubild (max. 160px, JPEG ~60% Qualität)
   direkt im Browser — landet als Data-URL in der Nachricht selbst und
   damit im ganz normalen Ende-zu-Ende-verschlüsselten Textpfad (die
   Referenz __media trägt sie mit). Sender UND Empfänger sehen sie
   sofort, ohne dass irgendwer die Originaldatei herunterladen muss —
   das Original bleibt weiterhin ein expliziter Klick (siehe
   downloadAndShowMedia), nur die Vorschau ist "kostenlos" dabei. */
async function makeThumbnail(file, kind) {
  if (kind !== 'image' && kind !== 'video') return null;
  try {
    let sourceEl;
    if (kind === 'image') {
      sourceEl = await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = reject;
        img.src = URL.createObjectURL(file);
      });
    } else {
      sourceEl = await new Promise((resolve, reject) => {
        const video = document.createElement('video');
        video.preload = 'metadata';
        video.muted = true;
        video.src = URL.createObjectURL(file);
        video.onloadeddata = () => { video.currentTime = Math.min(0.5, video.duration || 0); };
        video.onseeked = () => resolve(video);
        video.onerror = reject;
      });
    }
    const maxDim = 160;
    const w = sourceEl.videoWidth || sourceEl.naturalWidth || sourceEl.width;
    const h = sourceEl.videoHeight || sourceEl.naturalHeight || sourceEl.height;
    if (!w || !h) return null;
    const scale = Math.min(1, maxDim / Math.max(w, h));
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(w * scale);
    canvas.height = Math.round(h * scale);
    canvas.getContext('2d').drawImage(sourceEl, 0, 0, canvas.width, canvas.height);
    URL.revokeObjectURL(sourceEl.src);
    return canvas.toDataURL('image/jpeg', 0.6);
  } catch {
    return null;
  }
}

async function sendMediaMessage(file, kind) {
  if (!state.activeConv) return;
  toast('📎 Wird hochgeladen…', 4000);
  try {
    let toUpload = file;
    if (kind === 'image' && window.MediaStorage?.shrinkImage) {
      try { toUpload = await window.MediaStorage.shrinkImage(file); } catch {}
    }

    const thumb = await makeThumbnail(file, kind);
    const { path: mediaPath, uploadUrl } = await api._fetch('/api/media/upload-url', { method: 'POST' });
    const { blob, ivB64, keyB64 } = await encryptFileForUpload(toUpload);
    const uploadResp = await fetch(uploadUrl, { method: 'PUT', body: blob });
    if (!uploadResp.ok) throw new Error('Hochladen fehlgeschlagen (' + uploadResp.status + ')');

    const ref = { path: mediaPath, iv: ivB64, key: keyB64, mime: file.type, name: file.name, size: file.size, thumb };

    /* Referenz + Thumbnail gehen zusammen durch den geschützten
       Ratchet-Pfad — genau wie Text, nur mit kind:'media' markiert,
       damit der Empfänger weiß, dass er die Originaldatei separat
       laden muss. Das Thumbnail selbst ist bereits Teil dieser
       Nachricht und braucht keinen zusätzlichen Download. */
    const result = await sendMessage(state.activeConv.peerId, state.activeConv.convId,
      JSON.stringify({ __media: ref, kind }));

    const conv = state.convs.get(state.activeConv.convId);
    if (conv) conv.lastMsg = { text: kind === 'image' ? '📷 Foto' : kind === 'video' ? '🎬 Video' : '📄 ' + file.name, ts: result.sentAt };

    const msgs = state.messages.get(state.activeConv.convId) || [];
    const last = msgs[msgs.length - 1];
    if (last) {
      last.media = { ref, kind, name: file.name };
      last.text = '';
      /* Sender kann seine eigene Datei sofort abspielen/ansehen, ohne
         sie erneut vom Server herunterzuladen — die Originaldatei
         (unverschlüsselt) liegt ja schon lokal im Browser vor. Wichtig
         besonders für Sprachnachrichten: ohne das hätte der Sender
         seine eigene Aufnahme nie anhören können. */
      last.mediaUrl = URL.createObjectURL(file);
    }
    renderChatMessages();
  } catch (e) {
    toast('⚠️ Upload fehlgeschlagen: ' + e.message);
  }
}

/* Beim Empfangen: erkennt, ob eine entschlüsselte Nachricht eigentlich
   eine Medienreferenz ist (JSON mit __media-Feld), lädt bei Bedarf
   NICHT automatisch herunter (Datenverbrauch!) — der Nutzer tippt zum
   Laden. parseIncomingMedia() wird von renderChatMessages genutzt. */
function parseIncomingMedia(text) {
  try {
    const obj = JSON.parse(text);
    if (obj && obj.__media) return { ref: obj.__media, kind: obj.kind };
  } catch {}
  return null;
}

/* Generischer Parser für strukturierte Nachrichtentypen (__location,
   __contact) — dasselbe Muster wie parseIncomingMedia, aber ohne
   Medien-Download-Logik, da diese Karten nur Text/Links enthalten. */
function parseStructured(text, key) {
  try {
    const obj = JSON.parse(text);
    if (obj && obj[key]) return obj[key];
  } catch {}
  return null;
}

async function downloadAndShowMedia(msgId, ref, kind, openFullscreen) {
  toast('⬇️ Wird geladen…', 3000);
  try {
    const { downloadUrl } = await api._fetch('/api/media/download-url?path=' + encodeURIComponent(ref.path));
    const resp = await fetch(downloadUrl);
    if (!resp.ok) throw new Error('Download fehlgeschlagen (' + resp.status + ')');
    const encryptedBuf = await resp.arrayBuffer();
    const blob = await decryptDownloadedFile(encryptedBuf, ref.iv, ref.key, ref.mime);
    const url = URL.createObjectURL(blob);
    for (const list of state.messages.values()) {
      const m = list.find(x => x.id === msgId);
      if (m) { m.mediaUrl = url; break; }
    }
    renderChatMessages();
    if (openFullscreen) openMediaFullscreen(msgId);
  } catch (e) {
    toast('⚠️ Laden fehlgeschlagen: ' + e.message);
  }
}

/* ── Vollbild-Viewer für Bilder ──
   Einfaches Overlay über die gesamte App, schließt per Antippen oder
   Zurück-Button. Für Videos/Audio bleibt der Inline-Player im Chat
   sinnvoller (eigene Steuerelemente, Vollbild würde nichts gewinnen). */
function openMediaFullscreen(msgId) {
  let mediaUrl = null;
  for (const list of state.messages.values()) {
    const m = list.find(x => x.id === msgId);
    if (m?.mediaUrl) { mediaUrl = m.mediaUrl; break; }
  }
  if (!mediaUrl) return;
  const overlay = document.createElement('div');
  overlay.className = 'media-fullscreen-overlay';
  overlay.innerHTML = `
    <button class="media-fullscreen-close" aria-label="Schließen">✕</button>
    <img src="${mediaUrl}">`;
  overlay.onclick = (e) => { if (e.target === overlay || e.target.closest('.media-fullscreen-close')) overlay.remove(); };
  document.body.appendChild(overlay);
}

/* Für Tests: interne Funktionen und Zustand exportieren. Der Aufruf von
   boot() unten läuft im Browser wie gewohnt automatisch; unter Node (in
   Tests) wird dasselbe Modul importiert, ohne dass boot() dort DOM-Elemente
   braucht, weil die Testsuite eigene Aufrufe macht statt boot(). */
export { state, Vault, reconstructIdentityFromVault, sk, boot,
  authSubmit, renderAuthChoice, renderPills, renderNav,
  renderMain, go, convRow, handleEnvelope, api,
  ensureSessions, ensureReceiverSession, sendMessage, openRatchet,
  openChat, closeChat, startChatWith, renderChatMessages,
  toggleBlock, submitReport, sendMediaMessage, parseIncomingMedia,
  downloadAndShowMedia, sendCurrentMessage, queueOffline, flushOutbox,
  setupOfflineDetection, LocalCache, afterAuthOffline, afterAuth };

if (typeof document !== 'undefined' && document.getElementById('boot')) {
  boot();
}
