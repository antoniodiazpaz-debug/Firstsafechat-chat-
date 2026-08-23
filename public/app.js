/* ═══════════════════════════════════════════════════════════════════════
   APP — verbindet crypto-core.js und api-client.js zu einer echten
   Anwendung. Anders als die alte index.html-Simulation spricht das
   hier den echten Server über HTTP/WebSocket an.
   ═══════════════════════════════════════════════════════════════════════ */
import { P, PreKeys, KT, X3DH, Ratchet, MAX_SKIP, b64, ub64, hexs, te, td } from '/crypto-core.js';
import { ApiClient, hashContact } from '/api-client.js';
import { setLocale, getLocale, t } from '/i18n.js';
import { detectLanguage, guessDialCode, preparePhoneInput, watchForSmsCode } from '/device-info.js';
import { initCallUI } from '/call-ui.js';
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
const Vault = {
  _dbp: null,
  _db() {
    if (this._dbp) return this._dbp;
    this._dbp = new Promise((resolve, reject) => {
      /* Version 2: zusätzlicher 'messages'-Store für den lokalen
         Nachrichten-Cache (siehe LocalCache unten) — nötig, damit die
         App offline überhaupt etwas anzuzeigen hat. Der Store liegt in
         derselben Datenbank wie der Schlüssel-Vault, aber getrennt
         verschlüsselt (siehe LocalCache.save). */
      /* Version 3: zusätzlicher 'deviceKey'-Store für den nicht-
         extrahierbaren AES-Schlüssel, der jetzt an die Stelle des
         Passworts tritt (siehe Vault._deviceKey). */
      const req = indexedDB.open('securechat-vault', 3);
      req.onupgradeneeded = e => {
        const db = req.result;
        if (!db.objectStoreNames.contains('identities'))
          db.createObjectStore('identities', { keyPath: 'deviceId' });
        if (!db.objectStoreNames.contains('messages'))
          db.createObjectStore('messages', { keyPath: 'deviceId' });
        if (!db.objectStoreNames.contains('deviceKey'))
          db.createObjectStore('deviceKey', { keyPath: 'id' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this._dbp;
  },
  /* Nicht-extrahierbarer AES-256-Schlüssel, einmal pro Gerät erzeugt.
     WebCrypto garantiert, dass ein mit extractable:false erzeugter
     CryptoKey NIE als Rohbytes an JavaScript herausgegeben werden kann —
     auch nicht durch Code auf derselben Seite (siehe W3C Web Crypto API
     Spezifikation: "storing and retrieval of key material, without ever
     exposing that key material to the application"). Das ersetzt die
     bisherige PBKDF2-Ableitung aus einem Passwort: statt "etwas, das der
     Nutzer weiß" schützt jetzt "ein Geheimnis, das an diesen Browser
     gebunden ist und diesen nie in lesbarer Form verlässt". Der
     CryptoKey selbst liegt in einem eigenen IndexedDB-Objektspeicher,
     getrennt vom verschlüsselten Datenblock — ein Angreifer mit
     Lesezugriff auf die Datenbank bekommt zwar den CryptoKey-Datensatz,
     kann daraus aber keine Bytes extrahieren, die außerhalb dieses
     Browserprofils nutzbar wären. */
  async _deviceKey() {
    const db = await this._db();
    const existing = await new Promise((resolve, reject) => {
      const tx = db.transaction('deviceKey', 'readonly');
      const req = tx.objectStore('deviceKey').get('main');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (existing) return existing.key;

    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await new Promise((resolve, reject) => {
      const tx = db.transaction('deviceKey', 'readwrite');
      tx.objectStore('deviceKey').put({ id: 'main', key });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    return key;
  },
  async save(deviceId, identityStore, meta) {
    const db = await this._db();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this._deviceKey();
    const plain = te.encode(JSON.stringify({
      IK: identityStore.IK.privJwk,
      IKS: identityStore.IKS.privJwk,
      SPK: identityStore.SPK.privJwk,
      opks: [...identityStore.opks].map(([id, k]) => [id, k.privJwk])
    }));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
    return new Promise((resolve, reject) => {
      const tx = db.transaction('identities', 'readwrite');
      tx.objectStore('identities').put({
        deviceId, iv: [...iv], ct: [...new Uint8Array(ct)], meta
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
  async load(deviceId) {
    const db = await this._db();
    const rec = await new Promise((resolve, reject) => {
      const tx = db.transaction('identities', 'readonly');
      const req = tx.objectStore('identities').get(deviceId);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (!rec) return null;
    const key = await this._deviceKey();
    let plain;
    try {
      plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(rec.iv) }, key, new Uint8Array(rec.ct));
    } catch {
      /* Sollte praktisch nie auftreten (der Geräteschlüssel ändert sich
         nie von selbst), außer die IndexedDB-Datenbank wurde manuell
         manipuliert oder ist beschädigt. */
      return 'corrupt';
    }
    return { data: JSON.parse(td.decode(plain)), meta: rec.meta };
  },
  async knownDeviceId() {
    return localStorage.getItem('securechat:deviceId');
  },
  rememberDevice(deviceId, userName) {
    localStorage.setItem('securechat:deviceId', deviceId);
    localStorage.setItem('securechat:userName', userName);
  },

  forget() {
    localStorage.removeItem('securechat:deviceId');
    localStorage.removeItem('securechat:userName');
  }
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
  _key: null,   // AES-Schlüssel, wird beim Entsperren des Vaults gesetzt
  _deviceId: null,

  /* Wird von afterAuth()/afterAuthOffline() aufgerufen, sobald der Vault
     entsperrt ist — nutzt DENSELBEN nicht-extrahierbaren Geräteschlüssel
     wie Vault selbst (siehe Vault._deviceKey). Kein eigenes Passwort,
     keine eigene Ableitung mehr nötig: der Geräteschlüssel schützt
     gleichermaßen die Identitätsschlüssel wie den Nachrichten-Cache. */
  async unlock(deviceId) {
    this._deviceId = deviceId;
    this._key = await Vault._deviceKey();
  },

  /* Konversationsliste + Nachrichten in einem Rutsch sichern — bewusst
     kein Eintrag pro Nachricht (siehe persistent_storage_for_artifacts-
     Grundsatz: zusammengehörige Daten in einem Schlüssel bündeln,
     statt viele kleine Schreibvorgänge zu erzeugen). */
  async save() {
    if (!this._key || !this._deviceId) return;
    const snapshot = {
      convs: [...state.convs.entries()],
      messages: [...state.messages.entries()],
      outbox: state.outbox,
      savedAt: Date.now()
    };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = te.encode(JSON.stringify(snapshot));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this._key, plain);
    const db = await Vault._db();
    await new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.objectStore('messages').put({ deviceId: this._deviceId, iv: [...iv], ct: [...new Uint8Array(ct)] });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  },

  /* Beim Start (online oder offline) den letzten bekannten Stand laden,
     BEVOR überhaupt ein Netzwerkaufruf versucht wird — so zeigt die
     Chat-Liste sofort etwas an, auch wenn der Server nicht antwortet. */
  async load() {
    if (!this._key || !this._deviceId) return false;
    const db = await Vault._db();
    const rec = await new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readonly');
      const req = tx.objectStore('messages').get(this._deviceId);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (!rec) return false;
    try {
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(rec.iv) }, this._key, new Uint8Array(rec.ct));
      const snapshot = JSON.parse(td.decode(plain));
      state.convs = new Map(snapshot.convs);
      state.messages = new Map(snapshot.messages);
      state.outbox = snapshot.outbox || [];
      return true;
    } catch (e) {
      console.warn('Lokaler Nachrichten-Cache nicht lesbar:', e.message);
      return false;
    }
  },

  /* Regelmäßig speichern statt bei jeder einzelnen Nachricht — spart
     IndexedDB-Schreibvorgänge bei einer Serie schnell eintreffender
     Nachrichten, ohne nennenswerte Verzögerung für den Nutzer. */
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
      el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:900;' +
        'background:var(--warn);color:#3a2a00;text-align:center;font-size:12.5px;' +
        'font-weight:600;padding:6px 12px;padding-top:calc(6px + env(safe-area-inset-top))';
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
  setupOfflineDetection();
  updateOfflineBanner();

  $('#bootMsg').textContent = 'Verbindung wird geprüft…';
  try {
    await api._fetch('/api/health', { auth: false });
  } catch (e) {
    /* Kein Server erreichbar heißt nicht zwangsläufig "App unbenutzbar".
       Ist bereits ein Gerät bekannt (localStorage), kann der Nutzer
       trotzdem seinen Vault öffnen und bereits empfangene Nachrichten
       lesen — nur Senden/Empfangen bleibt bis zur Verbindung aus. Nur
       wenn NICHTS bekannt ist (erster Start), ist ohne Server nichts
       möglich, weil Registrierung zwingend online passieren muss. */
    const knownDevice = await Vault.knownDeviceId();
    if (!knownDevice) {
      $('#bootMsg').textContent = 'Server nicht erreichbar. Bitte später erneut versuchen.';
      return;
    }
    state.isOffline = true;
  }

  const knownDevice = await Vault.knownDeviceId();
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
async function renderLoginForKnownDevice(deviceId, userName) {
  $('#bootMsg').textContent = 'Automatische Anmeldung …';
  $('#boot').classList.remove('hide');

  try {
    const vaultRec = await Vault.load(deviceId);
    if (!vaultRec || vaultRec === 'corrupt' || !vaultRec.meta?.token) {
      throw new Error('vault-unusable');
    }
    state.identity = await reconstructIdentityFromVault(vaultRec.data);

    let me;
    try {
      me = await api._fetch('/api/me', { auth: false, headers: { Authorization: 'Bearer ' + vaultRec.meta.token } });
    } catch (e) {
      if (e.status === 401) throw new Error('token-expired');
      /* Server nicht erreichbar, Vault aber lesbar — Offline-Modus,
         genau wie zuvor beim Passwort-Pfad. */
      $('#boot').classList.add('hide');
      await afterAuthOffline(deviceId, userName);
      return;
    }

    api.token = vaultRec.meta.token;
    await afterAuth({ token: vaultRec.meta.token, user: me.user, device: me.device });
  } catch (e) {
    $('#boot').classList.add('hide');
    /* Token abgelaufen (nach 30 Tagen Inaktivität) oder Vault
       beschädigt: dieses Gerät kann sich nicht mehr automatisch
       anmelden. Ohne Passwort gibt es keinen Weg, den ALTEN Zugang
       wiederherzustellen — die einzig verbleibende Option ist eine
       neue Registrierung (das alte Konto bleibt auf dem Server
       bestehen, ein anderes bereits angemeldetes Gerät könnte dieses
       hier stattdessen über Pairing neu koppeln, falls eines existiert). */
    Vault.forget();
    renderAuthChoice();
    if (e.message === 'token-expired') {
      authErr('Sitzung abgelaufen — bitte neu registrieren oder ein anderes angemeldetes Gerät zum Koppeln nutzen.');
    }
  }
}

async function reconstructIdentityFromVault(data) {
  const importDH = jwk => crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const importSign = jwk => crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const pubOnly = jwk => { const c = { ...jwk }; delete c.d; return c; };
  const IK = { priv: await importDH(data.IK), privJwk: data.IK, pubJwk: pubOnly(data.IK) };
  const IKS = { priv: await importSign(data.IKS), privJwk: data.IKS, pubJwk: pubOnly(data.IKS) };
  const SPK = { priv: await importDH(data.SPK), privJwk: data.SPK, pubJwk: pubOnly(data.SPK) };
  const opks = new Map();
  for (const [id, jwk] of data.opks) {
    opks.set(id, { priv: await importDH(jwk), privJwk: jwk, pubJwk: pubOnly(jwk) });
  }
  return { IK, IKS, SPK, opks, opkSeq: opks.size, spkId: 1, consumed: 0,
    spkMeta: { spkId: 1, createdAt: Date.now(), sig: null } };
}

/* ═══════════════════════════════════════════════════════════════════════
   NACH ERFOLGREICHER ANMELDUNG
   ═══════════════════════════════════════════════════════════════════════ */
async function afterAuth(data) {
  state.me = data.user;
  state.device = data.device;
  state.monitor = new KT.Monitor();

  /* WICHTIG: window.__app muss HIER gesetzt werden, nicht erst in
     renderShell() — die E-Mail-Verifizierung (Pflicht, siehe unten)
     kann einen frühen return auslösen, BEVOR renderShell() je läuft.
     Das Verifizierungs-Overlay braucht window.__app.submitEmailCode()
     aber bereits an diesem Punkt — ohne diese Zeile hier bleiben seine
     Buttons wirkungslos (window.__app wäre schlicht undefined), was
     sich als "auf den Buttons passiert nichts" zeigt, ganz ohne
     sichtbaren Fehler, weil das onclick-Attribut selbst still auf
     einer nicht existierenden Eigenschaft scheitert. */
  window.__app = appActions;

  /* Lokalen Nachrichten-Cache entsperren und zuerst laden — damit die
     Chat-Liste sofort etwas zeigt, auch bevor die Inbox vom Server
     abgeglichen ist. Nutzt denselben Geräteschlüssel wie der Vault,
     kein separates Geheimnis mehr nötig. */
  await LocalCache.unlock(data.device.id);
  await LocalCache.load();

  api.connect();
  wireSocketEvents();

  try { await window.StorageGuard?.requestPersistence?.(); } catch {}
  await loadBlockList();
  await refreshInbox();

  /* E-Mail-Verifizierung ist jetzt PFLICHT (siehe server.js — Registrierung
     ohne verifizierbare E-Mail schlägt dort bereits fehl) — deshalb hier
     VOR dem Rendern der Hauptoberfläche prüfen, nicht danach. Ein Konto
     ohne bestätigte E-Mail kommt gar nicht erst in die App hinein. */
  if (!state.me.emailVerified) {
    showEmailVerifyPrompt(true);
    return;
  }

  $('#auth').classList.add('hide');
  $('#app').classList.remove('hide');
  renderShell();
  go('chats');
  toast('Willkommen, ' + state.me.name + ' 🔐');
}

function showEmailVerifyPrompt(blocking) {
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
     wurde. */
  document.getElementById('verifySubmitBtn').addEventListener('click', submitEmailCode);
  document.getElementById('verifyResendBtn').addEventListener('click', resendEmailCode);
  document.getElementById('verifyDismissBtn')?.addEventListener('click', dismissEmailVerify);
}

async function submitEmailCode() {
  const input = document.getElementById('verifyCodeInput');
  const errEl = document.getElementById('verifyError');
  const code = input?.value.trim();
  if (!code || code.length !== 6) {
    errEl.textContent = 'Bitte den 6-stelligen Code eingeben.';
    errEl.style.display = 'block';
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
    errEl.textContent = e.message === 'Code falsch' ? 'Falscher Code — bitte prüfen.'
      : e.message === 'Code abgelaufen — neuen anfordern' ? 'Code abgelaufen — tipp auf "Code erneut senden".'
      : e.message;
    errEl.style.display = 'block';
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

  await LocalCache.load();

  $('#auth').classList.add('hide');
  $('#app').classList.remove('hide');
  renderShell();
  go('chats');
  updateOfflineBanner();
  toast('📵 Offline — zeige gespeicherten Verlauf. Senden folgt, sobald du wieder online bist.', 3500);
}

function wireSocketEvents() {
  api.on('envelope', onIncomingEnvelope);
  api.on('presence', onPresence);
  initCallUI(api);
  api.on('device-added', d => toast('Neues Gerät verbunden: ' + (d.device?.name || '')));
  api.on('device-revoked', () => {
    toast('Dieses Gerät wurde entfernt. Du wirst abgemeldet.');
    setTimeout(() => { Vault.forget(); location.reload(); }, 1500);
  });
  api.on('contact-joined', async () => {
    toast('Ein Kontakt nutzt jetzt auch SecureChat 👋');
  });
  api.on('need-prekeys', () => refillPrekeys().catch(() => {}));
  api.on('connected', () => {
    state.isOffline = false;
    updateOfflineBanner();
    toast('Verbunden', 1200);
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
async function handleEnvelope(env, live) {
  const convId = env.convId || ('dm_' + [state.me.id, env.senderId].filter(Boolean).sort().join('_'));
  let plaintext = '[verschlüsselt]';
  try {
    if (env.sealed) {
      plaintext = await openSealed(env);
    } else {
      plaintext = await openRatchet(env);
    }
  } catch (e) {
    console.warn('Entschlüsselung fehlgeschlagen:', e.message);
    plaintext = '⚠️ Nicht entschlüsselbar';
  }

  if (!state.messages.has(convId)) state.messages.set(convId, []);
  state.messages.get(convId).push({
    id: env.id, from: env.senderId || '(versiegelt)', text: plaintext,
    ts: env.sentAt, mine: false, sealed: !!env.sealed
  });

  const conv = state.convs.get(convId) || { convId, peerId: env.senderId, unread: 0 };
  conv.lastMsg = { text: plaintext, ts: env.sentAt };
  conv.unread = (conv.unread || 0) + 1;
  state.convs.set(convId, conv);
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
  $('#app').innerHTML = `
    <div class="topbar">
      <h1>SecureChat</h1>
      <div class="topicons">
        <button class="iconbtn" onclick="window.__app.openCamera()">📷</button>
        <button class="iconbtn" onclick="window.__app.mainMenu(event)">⋮</button>
      </div>
    </div>
    <div class="searchwrap">
      <div class="search"><span class="ic">🔍</span>
        <input id="searchInput" placeholder="Meta AI fragen oder suchen" oninput="window.__app.onSearch(this.value)"></div>
    </div>
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
  const tabs = [
    ['chats', '💬', 'Chats', totalUnread],
    ['updates', '📸', 'Aktuelles', 0],
    ['communities', '👥', 'Communitys', 0],
    ['calls', '📞', 'Anrufe', 0]
  ];
  $('#navbar').innerHTML = tabs.map(([id, ic, lb, bdg]) => `
    <button class="${state.tab === id ? 'on' : ''}" onclick="window.__app.go('${id}')">
      <span class="navic">${ic}</span><span class="navlb">${lb}</span>
      ${bdg ? `<span class="navbdg"></span>` : ''}
    </button>`).join('');
}

function go(tab) {
  state.tab = tab; state.view = 'list';
  renderNav(); renderMain();
}

function renderMain() {
  if (state.view !== 'list') return;
  const main = $('#main');
  if (!main) return;
  if (state.tab !== 'chats') {
    main.innerHTML = `<div class="empty"><div class="ic">🚧</div><div>Noch nicht verfügbar</div></div>`;
    return;
  }

  let convs = [...state.convs.values()];
  if (activePill === 'unread') convs = convs.filter(c => (c.unread || 0) > 0);
  if (activePill === 'groups') convs = convs.filter(c => c.isGroup);
  if (state.search) {
    const q = state.search.toLowerCase();
    convs = convs.filter(c => (c.name || c.peerId || '').toLowerCase().includes(q));
  }
  convs.sort((a, b) => (b.lastMsg?.ts || 0) - (a.lastMsg?.ts || 0));

  main.innerHTML = `
    <div class="lockedrow"><span class="ic">🔒</span><span>Gesperrte Chats</span></div>
    <div class="scroll" style="height:calc(100% - 46px);position:relative">
      ${convs.length ? convs.map((c, i) => convRow(c, i)).join('') :
        `<div class="empty"><div class="ic">💬</div><div>Noch keine Chats.<br>Tippe auf + um zu starten.</div></div>`}
      <div class="fab" onclick="window.__app.newChat()">💬</div>
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
  return `
    <div class="row" onclick="window.__app.openConv(${i})">
      <div class="av">${avatar}${c.isGroup ? '' : `<div class="dot ${c.online ? 'online' : 'offline'}"></div>`}</div>
      <div class="meta">
        <div class="l1"><span class="nm">${esc(name)}</span>
          <span class="tm ${unread ? 'un' : ''}">${c.lastMsg ? time(c.lastMsg.ts) : ''}</span></div>
        <div class="l2"><span class="pv">${preview}</span>
          ${unread ? `<span class="unread">${unread}</span>` : ''}</div>
      </div>
    </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════
   AKTIONEN, vom UI aufgerufen
   ═══════════════════════════════════════════════════════════════════════ */
const appActions = {
  setPill(id) { activePill = id; renderPills(); renderMain(); },
  onSearch(v) { state.search = v; renderMain(); },
  go(tab) { go(tab); },
  openConv(i) { const c = window.__conv[i]; openChat(c); },
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
  closeChat() { closeChat(); },
  sendClick() { sendCurrentMessage(); },
  inputKey(e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendCurrentMessage(); } },
  startChatWith(userId) { startChatWith(userId); },
  chatMenu(e) { chatMenu(e); },
  toggleBlock() { toggleBlock(); },
  reportUser() { reportUser(); },
  submitReport() { submitReport(); },
  attachSheet() { attachSheet(); },
  pickMedia(accept, kind) { pickMedia(accept, kind); },
  loadMedia(msgId) {
    for (const list of state.messages.values()) {
      const m = list.find(x => x.id === msgId);
      if (m) {
        const media = m.media || parseIncomingMedia(m.text);
        if (media) downloadAndShowMedia(msgId, media.ref, media.kind);
        break;
      }
    }
  }
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
  if (usedOpk) state.identity.opks.delete(opkId);
  return st;
}

/* ═══════════════════════════════════════════════════════════════════════
   NACHRICHT SENDEN — Fanout an alle aktiven Empfängergeräte
   ═══════════════════════════════════════════════════════════════════════ */
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

  const conv = state.convs.get(convId) || { convId, peerId };
  conv.lastMsg = { text: plaintext, ts: result.sentAt };
  conv.unread = 0;
  state.convs.set(convId, conv);

  if (!state.messages.has(convId)) state.messages.set(convId, []);
  state.messages.get(convId).push({ id: 'local-' + result.sentAt, text: plaintext, ts: result.sentAt, mine: true });
  LocalCache.scheduleSave();
  return result;
}

async function sendCurrentMessage() {
  const input = $('#msgInput');
  if (!input) return;
  const text = input.value.trim();
  if (!text || !state.activeConv) return;
  input.value = '';
  input.style.height = 'auto';
  const { peerId, convId } = state.activeConv;

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
      <div class="av" style="width:38px;height:38px;font-size:16px">${(c.name || '?')[0].toUpperCase()}</div>
      <div class="name">
        <div class="nm">${esc(c.name || c.peerId)}</div>
        <div class="st" id="chatStatus">${c.online ? 'online' : 'offline'}</div>
      </div>
      <button class="iconbtn" onclick="window.__app.startCall('audio')" aria-label="Anrufen">📞</button>
      <button class="iconbtn" onclick="window.__app.startCall('video')" aria-label="Videoanruf">📹</button>
      <button class="iconbtn" onclick="window.__app.chatMenu(event)">⋮</button>
    </div>
    <div id="chatbody"></div>
    <div id="composer">
      <div class="cbar">
        <button class="iconbtn" onclick="window.__app.attachSheet()">📎</button>
        <div class="cin">
          <textarea id="msgInput" rows="1" placeholder="Nachricht"
            oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,110)+'px'"
            onkeydown="window.__app.inputKey(event)"></textarea>
        </div>
        <button class="sendbtn" onclick="window.__app.sendClick()">➤</button>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(overlay);

  ensureSessions(c.peerId).catch(e => toast('⚠️ ' + e.message));
  renderChatMessages();
  $('#msgInput')?.focus();
}

function closeChat() {
  const overlay = document.getElementById('chatOverlay');
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

    let content;
    if (media) {
      if (m.mediaUrl) {
        content = media.kind === 'image'
          ? `<div class="media"><img src="${m.mediaUrl}"></div>`
          : media.kind === 'video'
            ? `<div class="media"><video src="${m.mediaUrl}" controls></video></div>`
            : `<div class="filemsg">📄 <a href="${m.mediaUrl}" download style="color:inherit">${esc(media.name || 'Datei')}</a></div>`;
      } else {
        const icon = media.kind === 'image' ? '🖼️' : media.kind === 'video' ? '🎬' : '📄';
        content = `<div class="filemsg" style="cursor:pointer" onclick="window.__app.loadMedia('${m.id}')">
          ${icon} <span>${media.kind === 'image' ? 'Foto' : media.kind === 'video' ? 'Video' : (media.name || 'Datei')} — antippen zum Laden</span></div>`;
      }
    } else {
      content = `<div class="tx">${esc(m.text)}</div>`;
    }

    rows.push(`
      <div class="msgrow ${m.mine ? 'mine' : ''}">
        <div class="bub" style="${m.pending ? 'opacity:.65' : ''}">
          ${content}
          <div class="ft"><span class="tm">${time(m.ts)}</span>
            ${m.mine ? (m.pending
              ? `<span class="ck" title="Wird gesendet, sobald wieder online">🕐</span>`
              : `<span class="ck">✓✓</span>`) : ''}
            ${!m.mine && media ? `<span class="timerbadge" style="color:var(--sub);background:rgba(255,255,255,.08)"
              title="Direkt übertragen — Absender für den Speicherdienst sichtbar">📎 direkt</span>` : ''}</div>
        </div>
      </div>`);
  }
  body.innerHTML = rows.join('');
  body.scrollTop = body.scrollHeight;
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
      ${users.length ? users.map(u => `
        <div class="row" style="padding:8px 0" onclick="window.__app.startChatWith('${u.id}')">
          <div class="av">${esc((u.name || '?')[0].toUpperCase())}
            <div class="dot ${u.online ? 'online' : 'offline'}"></div></div>
          <div class="meta" style="border-bottom:none">
            <div class="l1"><span class="nm">${esc(u.name)}</span></div>
          </div>
        </div>`).join('') : `<div class="empty" style="height:auto;padding:24px"><div class="ic">👤</div><div>Noch keine anderen Nutzer</div></div>`}
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

function startChatWith(userId) {
  document.getElementById('newChatSheet')?.remove();
  const convId = 'dm_' + [state.me.id, userId].sort().join('_');
  let conv = state.convs.get(convId);
  if (!conv) {
    conv = { convId, peerId: userId, name: userId, unread: 0 };
    state.convs.set(convId, conv);
  }
  openChat(conv);
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
      <button class="btn ghost" style="width:100%;margin-top:16px" onclick="window.__app.logoutClick()">Abmelden</button>
      <button class="btn ghost" style="width:100%;margin-top:8px;color:#f15c6d" onclick="window.__app.showDeleteAccount()">Konto löschen</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
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
  const isBlocked = state.blocked.has(peerId);

  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'chatMenuSheet';
  sheet.onclick = ev => { if (ev.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="row" style="padding:10px 0" onclick="window.__app.reportUser()">
        <div style="font-size:20px;width:32px">🚩</div>
        <div class="meta" style="border-bottom:none"><div class="l1"><span class="nm">Melden</span></div></div>
      </div>
      <div class="row" style="padding:10px 0" onclick="window.__app.toggleBlock()">
        <div style="font-size:20px;width:32px">${isBlocked ? '✅' : '🚫'}</div>
        <div class="meta" style="border-bottom:none"><div class="l1">
          <span class="nm" style="color:${isBlocked ? 'var(--acc2)' : 'var(--dan)'}">
            ${isBlocked ? 'Entsperren' : 'Blockieren'}</span></div></div>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
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
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <div class="row" style="padding:10px 0" onclick="window.__app.pickMedia('image/*','image')">
        <div style="font-size:20px;width:32px">🖼️</div>
        <div class="meta" style="border-bottom:none"><div class="l1"><span class="nm">Foto</span></div></div>
      </div>
      <div class="row" style="padding:10px 0" onclick="window.__app.pickMedia('video/*','video')">
        <div style="font-size:20px;width:32px">🎬</div>
        <div class="meta" style="border-bottom:none"><div class="l1"><span class="nm">Video</span></div></div>
      </div>
      <div class="row" style="padding:10px 0" onclick="window.__app.pickMedia('*/*','file')">
        <div style="font-size:20px;width:32px">📄</div>
        <div class="meta" style="border-bottom:none"><div class="l1"><span class="nm">Datei</span></div></div>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

function pickMedia(accept, kind) {
  document.getElementById('attachSheet')?.remove();
  const input = document.createElement('input');
  input.type = 'file'; input.accept = accept;
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    await sendMediaMessage(file, kind);
  };
  input.click();
}

async function sendMediaMessage(file, kind) {
  if (!state.activeConv) return;
  if (!window.MediaStorage || !window.MEDIA_CONFIG?.uploadUrl) {
    toast('⚠️ Kein Medienspeicher konfiguriert — siehe media-storage.js/config.js');
    return;
  }
  toast('📎 Wird hochgeladen…', 4000);
  try {
    let toUpload = file;
    if (kind === 'image') {
      try { toUpload = await window.MediaStorage.shrinkImage(file); } catch {}
    }
    const uploaded = await window.MediaStorage.uploadMedia(toUpload,
      { uploadUrl: window.MEDIA_CONFIG.uploadUrl, kind });
    const ref = window.MediaStorage.mediaReference(uploaded);

    /* Nur die winzige Referenz (~250 Byte) geht durch den geschützten
       Ratchet-Pfad — genau wie Text, nur mit kind:'media' markiert,
       damit der Empfänger weiß, dass er die Datei separat laden muss. */
    const result = await sendMessage(state.activeConv.peerId, state.activeConv.convId,
      JSON.stringify({ __media: ref, kind }));

    const conv = state.convs.get(state.activeConv.convId);
    if (conv) conv.lastMsg = { text: kind === 'image' ? '📷 Foto' : kind === 'video' ? '🎬 Video' : '📄 ' + file.name, ts: result.sentAt };

    const msgs = state.messages.get(state.activeConv.convId) || [];
    const last = msgs[msgs.length - 1];
    if (last) { last.media = { ref, kind, name: file.name }; last.text = ''; }
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

async function downloadAndShowMedia(msgId, ref, kind) {
  if (!window.MediaStorage || !window.MEDIA_CONFIG?.downloadUrl) {
    toast('⚠️ Kein Medienspeicher konfiguriert'); return;
  }
  toast('⬇️ Wird geladen…', 3000);
  try {
    const blob = await window.MediaStorage.downloadMedia(ref, { downloadUrl: window.MEDIA_CONFIG.downloadUrl });
    const url = URL.createObjectURL(blob);
    for (const list of state.messages.values()) {
      const m = list.find(x => x.id === msgId);
      if (m) { m.mediaUrl = url; break; }
    }
    renderChatMessages();
  } catch (e) {
    toast('⚠️ Laden fehlgeschlagen: ' + e.message);
  }
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
