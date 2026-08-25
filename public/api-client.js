/* ═══════════════════════════════════════════════════════════════════════
   API-CLIENT — echte Verbindung zu server.js
   ─────────────────────────────────────────────────────────────────────
   Ersetzt die In-Memory-Zwei-Personen-Simulation aus der ursprünglichen
   index.html durch echte HTTP-/WebSocket-Aufrufe. Die Krypto-Primitive
   (P, PreKeys, X3DH, Ratchet, KT) sind unverändert — nur die Transport-
   schicht ist neu.

   Grundprinzip: Dieses Modul kennt das SERVER-API (Fanout, Geräte,
   Pairing), aber keine UI. Es liefert Rohdaten und Ereignisse; die
   Darstellung macht app.js.
   ═══════════════════════════════════════════════════════════════════════ */

const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export class ApiClient {
  constructor(baseUrl) {
    this.base = baseUrl.replace(/\/$/, '');
    this.token = null;
    this.deviceId = null;
    this.userId = null;
    this.ws = null;
    this.listeners = new Map();   // eventType → Set<fn>
    this._wsQueue = [];
  }

  on(event, fn) {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event).add(fn);
    return () => this.listeners.get(event)?.delete(fn);
  }
  _emit(event, data) {
    for (const fn of (this.listeners.get(event) || [])) {
      try { fn(data); } catch (e) { console.error(`Listener für "${event}" warf:`, e); }
    }
  }

  async _fetch(path, { method = 'GET', body, headers = {}, auth = true } = {}) {
    const h = { 'Content-Type': 'application/json', ...headers };
    if (auth && this.token) h.Authorization = 'Bearer ' + this.token;

    /* OHNE Timeout kann fetch() auf manchen Mobilfunkverbindungen (z. B.
       bei einem Wechsel zwischen WLAN und Mobilfunk mitten in der
       Anfrage, oder bei bestimmten DNS-Problemen) UNBEGRENZT hängen
       bleiben — die Fetch-API selbst hat keinen eingebauten Timeout.
       Das zeigt sich exakt als endlos drehender Ladebildschirm, noch
       bevor jeglicher nachgelagerter Code (IndexedDB, Countdown-Anzeige
       o. Ä.) je erreicht wird, weil das await hier selbst nie zurückkehrt. */
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    let res;
    try {
      res = await fetch(this.base + path, {
        method, headers: h, body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });
    } catch (err) {
      if (err.name === 'AbortError') {
        const timeoutErr = new Error('Zeitüberschreitung — Server antwortet nicht');
        timeoutErr.status = 0;
        throw timeoutErr;
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }

    let data;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) {
      const err = new Error(data?.error || `HTTP ${res.status}`);
      err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  }

  /* ── Konten ── */
  async register({ name, password, email, phone, deviceName, platform, identity }) {
    const data = await this._fetch('/api/register', { auth: false, method: 'POST', body: {
      name, password, email, phone, deviceName, platform,
      ikDH: identity.IK.pubJwk, ikSign: identity.IKS.pubJwk,
      spk: { spkId: identity.spkMeta.spkId, pub: identity.SPK.pubJwk,
             signature: identity.spkMeta.sig, createdAt: identity.spkMeta.createdAt },
      /* identity.opks ist eine Map<opkId, Schlüsselobjekt> (siehe
         PreKeys.createStore in crypto-core.js), kein Array — [...map]
         liefert [id, key]-Paare, die hier zu {opkId, pub} umgeformt
         werden müssen. */
      opks: [...identity.opks].map(([opkId, key]) => ({ opkId, pub: key.pubJwk }))
    }});
    this._applySession(data);
    return data;
  }

  /* E-Mail-Bestätigungscode einreichen — wirft bei falschem/abgelaufenem
     Code, der Aufrufer fängt das ab und zeigt die Fehlermeldung an. */
  async verifyEmail(code) {
    return this._fetch('/api/verify-email', { method: 'POST', body: { code } });
  }

  /* Neuen Code anfordern, z. B. wenn der erste nie ankam. */
  async resendVerification() {
    return this._fetch('/api/resend-verification', { method: 'POST' });
  }

  /* Kontowiederherstellung — beide Aufrufe laufen bewusst OHNE
     bestehende Anmeldung (auth: false), das ist der ganze Zweck: der
     Nutzer hat gerade kein gültiges Sitzungstoken mehr. */
  async recoverRequest(email) {
    return this._fetch('/api/account/recover-request', { auth: false, method: 'POST', body: { email } });
  }
  async recoverVerify({ email, code, deviceName, platform, identity }) {
    const data = await this._fetch('/api/account/recover-verify', { auth: false, method: 'POST', body: {
      email, code, deviceName, platform,
      ikDH: identity.IK.pubJwk, ikSign: identity.IKS.pubJwk,
      spk: { spkId: identity.spkMeta.spkId, pub: identity.SPK.pubJwk,
             signature: identity.spkMeta.sig, createdAt: identity.spkMeta.createdAt },
      opks: [...identity.opks].map(([opkId, key]) => ({ opkId, pub: key.pubJwk }))
    }});
    this._applySession(data);
    return data;
  }

  /* Konto endgültig löschen — das Bearer-Token allein ist der
     Identitätsnachweis (es gibt kein Passwort mehr im System). Die
     bewusste Bestätigung passiert client-seitig (Namen exakt eintippen,
     siehe confirmDeleteAccount in app.js), nicht durch ein erneutes
     Geheimnis. */
  async deleteAccount() {
    return this._fetch('/api/account/delete', { method: 'POST' });
  }


  /* Erste Anmeldung auf einem GERÄT braucht deviceId aus lokalem Speicher.
     Ohne deviceId antwortet der Server mit 428 + needsPairing:true —
     der Aufrufer muss dann pairClaim() nutzen, nicht login() erneut. */
  /* UNGENUTZT seit der Umstellung auf passwortlose Anmeldung — app.js
     ruft diese Methode nicht mehr auf. Ein bekanntes Gerät meldet sich
     stattdessen direkt über das im Vault gespeicherte Sitzungstoken bei
     /api/me an (siehe renderLoginForKnownDevice). server.js akzeptiert
     diese Route technisch weiterhin, weil sie für direkte API-Aufrufer
     von außerhalb der App noch sinnvoll sein kann. */
  async login({ name, password, deviceId }) {
    const data = await this._fetch('/api/login', { auth: false, method: 'POST',
      body: { name, password, deviceId } });
    this._applySession(data);
    return data;
  }

  async logout() {
    await this._fetch('/api/logout', { method: 'POST' }).catch(() => {});
    this.disconnect();
    this.token = this.deviceId = this.userId = null;
  }

  _applySession(data) {
    this.token = data.token;
    this.deviceId = data.device?.id;
    this.userId = data.user?.id;
  }

  async me() { return this._fetch('/api/me'); }
  async updateProfile(fields) { return this._fetch('/api/profile', { method: 'POST', body: fields }); }
  async setAvatar(path) { return this._fetch('/api/profile/avatar', { method: 'POST', body: { path } }); }
  async listUsers() { return this._fetch('/api/users'); }

  /* ── Geräte (Multi-Device) ── */
  async pairRequest() { return this._fetch('/api/devices/pair-request', { method: 'POST' }); }

  async pairClaim({ code, deviceName, platform, identity }) {
    const data = await this._fetch('/api/devices/pair-claim', { auth: false, method: 'POST', body: {
      code, deviceName, platform,
      ikDH: identity.IK.pubJwk, ikSign: identity.IKS.pubJwk,
      spk: { spkId: identity.spkMeta.spkId, pub: identity.SPK.pubJwk,
             signature: identity.spkMeta.sig, createdAt: identity.spkMeta.createdAt },
      opks: [...identity.opks].map(([opkId, key]) => ({ opkId, pub: key.pubJwk }))
    }});
    this._applySession(data);
    return data;
  }

  async listDevices() { return this._fetch('/api/devices'); }
  async revokeDevice(deviceId) { return this._fetch('/api/devices/revoke', { method: 'POST', body: { deviceId } }); }

  /* ── Push ── */
  async pushSubscribe({ platform, endpoint, p256dh, auth }) {
    return this._fetch('/api/push/subscribe', { method: 'POST', body: { platform, endpoint, p256dh, auth } });
  }
  async pushUnsubscribe() { return this._fetch('/api/push/unsubscribe', { method: 'POST' }); }

  /* ── Kontaktabgleich ── */
  async syncContacts(hashes) { return this._fetch('/api/contacts/sync', { method: 'POST', body: { hashes } }); }

  /* ── Prekeys ── */
  async fetchBundle(userId, deviceId = null) {
    const q = deviceId ? `?user=${userId}&device=${deviceId}` : `?user=${userId}`;
    return this._fetch('/api/bundle' + q);
  }
  async uploadPrekeys({ spk, opks }) { return this._fetch('/api/prekeys', { method: 'POST', body: { spk, opks } }); }
  async rotateIdentity(ikDH) { return this._fetch('/api/rotate-identity', { method: 'POST', body: { ikDH } }); }

  /* ── Sealed Sender ── */
  async senderCertificate() { return this._fetch('/api/sender-certificate'); }
  async setAccessKey(uak, allowSealed = true) {
    return this._fetch('/api/access-key', { method: 'POST', body: { uak, allowSealed } });
  }
  /* perDevice: [{deviceId, sealed}] — kein Bearer-Token, UAK im Header */
  async sendSealed(recipientId, uak, convId, perDevice, gossip) {
    return this._fetch('/api/send-sealed', {
      auth: false, method: 'POST',
      headers: { 'X-Unidentified-Access-Key': uak },
      body: { recipientId, convId, perDevice, gossip }
    });
  }

  /* ── Nachrichten ──
     perDevice: [{deviceId, header, ciphertext}] — ein Eintrag pro
     aktivem Empfängergerät (Fanout). Der Aufrufer hat vorher per
     fetchBundle() die Geräteliste geholt und für jedes einen eigenen
     Ratchet-Zustand aufgebaut/benutzt. */
  async send({ recipientId, convId, groupId, kind, perDevice, gossip }) {
    return this._fetch('/api/send', { method: 'POST',
      body: { recipientId, convId, groupId, kind, perDevice, gossip } });
  }
  async inbox() { return this._fetch('/api/inbox'); }
  async ack(ids) { return this._fetch('/api/ack', { method: 'POST', body: { ids } }); }

  /* ── Blockieren & Melden ── */
  async block(userId) { return this._fetch('/api/block', { method: 'POST', body: { userId } }); }
  async unblock(userId) { return this._fetch('/api/unblock', { method: 'POST', body: { userId } }); }
  async blockedList() { return this._fetch('/api/blocks'); }
  async report({ reportedId, convId, reason, note, includedContent }) {
    return this._fetch('/api/report', { method: 'POST',
      body: { reportedId, convId, reason, note, includedContent } });
  }

  /* ── Gruppen ── */
  async createGroup({ name, avatar, members, wrapped }) {
    return this._fetch('/api/group', { method: 'POST', body: { name, avatar, members, wrapped } });
  }
  async myGroups() { return this._fetch('/api/groups'); }

  /* ── Key Transparency ── */
  async ktSth() { return this._fetch('/api/kt/sth', { auth: false }); }
  async ktProof(userId) { return this._fetch('/api/kt/proof?user=' + userId, { auth: false }); }
  async ktConsistency(from) { return this._fetch('/api/kt/consistency?from=' + from, { auth: false }); }
  async ktHistory(userId) { return this._fetch('/api/kt/history?user=' + userId, { auth: false }); }

  /* ── Mixnet ── */
  async mixDirectory() { return this._fetch('/api/mix/directory', { auth: false }); }
  async mixInject(firstHop, packetB64) {
    return this._fetch('/api/mix/inject', { auth: false, method: 'POST',
      body: { packet: packetB64, firstHop } });
  }

  /* ── WebSocket ──
     Liefert live: envelope, presence, typing, read, need-prekeys,
     device-added, device-revoked. Reconnect mit exponentiellem Backoff,
     damit ein kurzer Netzausfall nicht die gesamte Sitzung kappt. */
  connect() {
    if (this.ws && this.ws.readyState <= 1) return;
    const wsBase = this.base.replace(/^http/, 'ws');
    const sock = new WebSocket(`${wsBase}/?token=${encodeURIComponent(this.token)}`);
    this.ws = sock;
    this._backoff = this._backoff || 1000;

    sock.onopen = () => { this._backoff = 1000; this._emit('connected', {}); };
    sock.onmessage = e => {
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      this._emit(msg.type, msg);
      this._emit('*', msg);
    };
    sock.onclose = () => {
      this._emit('disconnected', {});
      if (this.token) {
        setTimeout(() => this.connect(), this._backoff);
        this._backoff = Math.min(this._backoff * 2, 30000);
      }
    };
    sock.onerror = () => {};
  }
  disconnect() {
    if (this.ws) { this.ws.onclose = null; this.ws.close(); this.ws = null; }
  }
  wsSend(obj) {
    if (this.ws?.readyState === 1) this.ws.send(JSON.stringify(obj));
  }
  ackViaSocket(ids) { this.wsSend({ type: 'ack', ids }); }
  sendTyping(to, convId) { this.wsSend({ type: 'typing', to, convId }); }
  sendRead(to, convId, ids) { this.wsSend({ type: 'read', to, convId, ids }); }
}

/* ── Kontaktabgleich: lokal hashen, nur Hashes senden ──
   Pfeffer und Normalisierung MÜSSEN exakt zu contactHash() in server.js
   passen — sonst matcht nie ein Hash. Der Pfeffer selbst ist kein
   Geheimnis (er steht im Server-Quelltext), er verhindert nur simples
   Rainbow-Table-Nachschlagen gegen rohe SHA-256(Nummer). */
const CONTACT_PEPPER = 'app-weiter-pfeffer-v1';
export async function hashContact(value) {
  if (!value) return null;
  const norm = String(value).replace(/[^\d+a-zA-Z@.]/g, '').toLowerCase();
  if (!norm) return null;
  const data = new TextEncoder().encode(norm + '|' + CONTACT_PEPPER);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return b64(digest);
}
