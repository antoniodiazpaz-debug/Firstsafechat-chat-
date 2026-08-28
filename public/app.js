/* ═══════════════════════════════════════════════════════════════════════
   APP — verbindet crypto-core.js und api-client.js zu einer echten
   Anwendung.
   ═══════════════════════════════════════════════════════════════════════ */
import { P, PreKeys, KT, X3DH, Ratchet, MAX_SKIP, b64, ub64, hexs, te, td } from '/crypto-core.js';
import { ApiClient, hashContact } from '/api-client.js';
import { setLocale, getLocale, t } from '/i18n.js';
import { detectLanguage, guessDialCode, preparePhoneInput, watchForSmsCode } from '/device-info.js';
import { Call } from '/call.js';

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
   VAULT — localStorage
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
      meta: { token, userName: localStorage.getItem('sc:userName') || '', email: localStorage.getItem('sc:email') || '' }
    };
  },
  knownDeviceId() { return localStorage.getItem('sc:deviceId'); },
  rememberDevice(deviceId, userName) {
    localStorage.setItem('sc:deviceId', deviceId);
    localStorage.setItem('sc:userName', userName);
  },
  forget() {
    ['sc:deviceId','sc:token','sc:userName','sc:email','sc:keys',
     'securechat:deviceId','securechat:userName','securechat:deviceKey']
      .forEach(k => localStorage.removeItem(k));
    Object.keys(localStorage).filter(k => k.startsWith('securechat:vault:')).forEach(k => localStorage.removeItem(k));
  },
  async _db() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('securechat', 2);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('messages')) db.createObjectStore('messages', { keyPath: 'deviceId' });
        if (!db.objectStoreNames.contains('sessions')) db.createObjectStore('sessions', { keyPath: 'key' });
      };
      req.onsuccess = e => resolve(e.target.result);
      req.onerror = () => reject(req.error);
    });
  }
};

/* ═══════════════════════════════════════════════════════════════════════
   SESSION STORE — FIX 1: Ratchet-Zustand dauerhaft in IndexedDB
   ═══════════════════════════════════════════════════════════════════════ */
const SessionStore = {
  /* Serialisiert einen Ratchet-Zustand: CryptoKey → JWK */
  async _serialize(st) {
    const exportKey = async k => {
      if (!k) return null;
      if (k.privJwk) return { privJwk: k.privJwk, pubJwk: k.pubJwk };
      try {
        const priv = await crypto.subtle.exportKey('jwk', k.priv || k);
        const pub  = k.pub ? await crypto.subtle.exportKey('jwk', k.pub) : null;
        return { privJwk: priv, pubJwk: pub };
      } catch { return null; }
    };
    const exportRaw = async k => {
      if (!k) return null;
      if (k instanceof ArrayBuffer) return b64(k);
      if (k instanceof Uint8Array) return b64(k.buffer);
      try { return b64(await crypto.subtle.exportKey('raw', k)); } catch { return null; }
    };
    const skipped = {};
    for (const [key, mk] of (st.skipped || new Map())) {
      skipped[key] = await exportRaw(mk);
    }
    return {
      RK:      await exportRaw(st.RK),
      DHs:     st.DHs ? await exportKey(st.DHs) : null,
      DHrJwk:  st.DHrJwk || null,
      CKs:     await exportRaw(st.CKs),
      CKr:     await exportRaw(st.CKr),
      Ns:      st.Ns, Nr: st.Nr, PN: st.PN,
      dhSteps: st.dhSteps,
      usedOpkId: st.usedOpkId || null,
      ephemeralJwk: st.ephemeral ? { privJwk: st.ephemeral.privJwk, pubJwk: st.ephemeral.pubJwk } : null,
      skipped
    };
  },

  /* Deserialisiert: JWK → CryptoKey */
  async _deserialize(raw) {
    const importDH = jwk => jwk ? crypto.subtle.importKey('jwk', jwk, { name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']) : null;
    const importRaw = b64str => {
      if (!b64str) return null;
      const buf = ub64(b64str);
      return buf.buffer;
    };
    const importKey = async obj => {
      if (!obj) return null;
      const priv = await importDH(obj.privJwk);
      const pub  = obj.pubJwk ? await crypto.subtle.importKey('jwk', obj.pubJwk, { name:'ECDH', namedCurve:'P-256' }, true, []) : null;
      return { priv, pub, privJwk: obj.privJwk, pubJwk: obj.pubJwk };
    };
    const skipped = new Map();
    for (const [key, val] of Object.entries(raw.skipped || {})) {
      if (val) skipped.set(key, importRaw(val));
    }
    const DHs = await importKey(raw.DHs);
    const DHr = raw.DHrJwk ? await crypto.subtle.importKey('jwk', raw.DHrJwk, { name:'ECDH', namedCurve:'P-256' }, true, []) : null;
    const ephemeral = raw.ephemeralJwk ? await importKey(raw.ephemeralJwk) : null;
    return {
      RK:      importRaw(raw.RK),
      DHs, DHr,
      DHrJwk:  raw.DHrJwk || null,
      CKs:     importRaw(raw.CKs),
      CKr:     importRaw(raw.CKr),
      Ns: raw.Ns, Nr: raw.Nr, PN: raw.PN,
      dhSteps: raw.dhSteps,
      usedOpkId: raw.usedOpkId || null,
      ephemeral,
      skipped,
      log: []
    };
  },

  async save(sessionKey, st) {
    try {
      const db = await Vault._db();
      const serialized = await this._serialize(st);
      await new Promise((resolve, reject) => {
        const tx = db.transaction('sessions', 'readwrite');
        tx.objectStore('sessions').put({ key: sessionKey, data: serialized });
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) { console.warn('Session speichern fehlgeschlagen:', e.message); }
  },

  async load(sessionKey) {
    try {
      const db = await Vault._db();
      const rec = await new Promise((resolve, reject) => {
        const tx = db.transaction('sessions', 'readonly');
        const req = tx.objectStore('sessions').get(sessionKey);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      if (!rec) return null;
      return await this._deserialize(rec.data);
    } catch (e) { console.warn('Session laden fehlgeschlagen:', e.message); return null; }
  },

  async loadAll() {
    try {
      const db = await Vault._db();
      const all = await new Promise((resolve, reject) => {
        const tx = db.transaction('sessions', 'readonly');
        const req = tx.objectStore('sessions').getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      const result = new Map();
      for (const rec of all) {
        try {
          result.set(rec.key, await this._deserialize(rec.data));
        } catch {}
      }
      return result;
    } catch { return new Map(); }
  }
};

/* ═══════════════════════════════════════════════════════════════════════
   LOCAL CACHE — Nachrichten-Cache
   ═══════════════════════════════════════════════════════════════════════ */
const LocalCache = {
  _key: null,
  _deviceId: null,
  async unlock(deviceId) {
    this._deviceId = deviceId;
    if (!this._key) {
      this._key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
    }
  },
  async save() {
    if (!this._key || !this._deviceId) return;
    const snapshot = { convs: [...state.convs.entries()], messages: [...state.messages.entries()], outbox: state.outbox, savedAt: Date.now() };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = te.encode(JSON.stringify(snapshot));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this._key, plain);
    const db = await Vault._db();
    if (!db) return;
    await new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.objectStore('messages').put({ deviceId: this._deviceId, iv: [...iv], ct: [...new Uint8Array(ct)] });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  },
  async load() {
    if (!this._key || !this._deviceId) return false;
    const db = await Vault._db();
    if (!db) return false;
    const rec = await new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readonly');
      const req = tx.objectStore('messages').get(this._deviceId);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (!rec) return false;
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(rec.iv) }, this._key, new Uint8Array(rec.ct));
      const snapshot = JSON.parse(td.decode(plain));
      state.convs = new Map(snapshot.convs);
      state.messages = new Map(snapshot.messages);
      state.outbox = snapshot.outbox || [];
      return true;
    } catch (e) { console.warn('Cache nicht lesbar:', e.message); return false; }
  },
  _saveTimer: null,
  scheduleSave() {
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => { this._saveTimer = null; this.save().catch(() => {}); }, 800);
  }
};

/* ═══════════════════════════════════════════════════════════════════════
   ZUSTAND
   ═══════════════════════════════════════════════════════════════════════ */
const state = {
  me: null, device: null, identity: null,
  view: 'list', tab: 'chats', activeConv: null,
  convs: new Map(), messages: new Map(), sessions: new Map(),
  bundleCache: new Map(), monitor: null, search: '',
  blocked: new Set(),
  isOffline: typeof navigator !== 'undefined' && navigator.onLine === false,
  outbox: []
};
const sk = (peerId, peerDeviceId) => peerId + '>' + peerDeviceId;

/* ═══════════════════════════════════════════════════════════════════════
   NETZSTATUS
   ═══════════════════════════════════════════════════════════════════════ */
function setupOfflineDetection() {
  if (typeof window === 'undefined' || !window.addEventListener) return;
  window.addEventListener('online',  () => { state.isOffline = false; updateOfflineBanner(); flushOutbox(); });
  window.addEventListener('offline', () => { state.isOffline = true;  updateOfflineBanner(); });
}
function updateOfflineBanner() {
  const bar = document.getElementById('offlineBar');
  if (state.isOffline) {
    if (!bar) {
      const el = document.createElement('div');
      el.id = 'offlineBar';
      el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:900;background:var(--warn);color:#3a2a00;text-align:center;font-size:12.5px;font-weight:600;padding:6px 12px;padding-top:calc(6px + env(safe-area-inset-top))';
      el.textContent = '⚠️ Keine Verbindung — Nachrichten werden gesendet, sobald du wieder online bist';
      document.body.prepend(el);
    }
  } else if (bar) bar.remove();
}
async function flushOutbox() {
  if (!state.outbox.length) return;
  const pending = [...state.outbox]; state.outbox = [];
  for (const item of pending) {
    try {
      await sendMessage(item.peerId, item.convId, item.text);
      const msgs = state.messages.get(item.convId);
      const local = msgs?.find(m => m.id === item.localId);
      if (local) local.pending = false;
    } catch { state.outbox.push(item); }
  }
  if (state.view === 'chat') renderChatMessages();
  renderMain();
}

/* ═══════════════════════════════════════════════════════════════════════
   BOOT
   ═══════════════════════════════════════════════════════════════════════ */
async function boot() {
  const bootMsgEarly = document.getElementById('bootMsg');
  if (bootMsgEarly) bootMsgEarly.textContent = 'Verbinde…';
  const resetTimeout = setTimeout(() => {
    const existing = document.getElementById('bootResetBtn');
    if (existing) return;
    const btn = document.createElement('button');
    btn.id = 'bootResetBtn';
    btn.textContent = '🔄 Zurücksetzen & neu starten';
    btn.style.cssText = 'margin-top:24px;padding:12px 20px;border-radius:12px;border:none;background:#f15c6d;color:#fff;font-size:15px;font-weight:600;display:block;margin-left:auto;margin-right:auto;cursor:pointer';
    btn.onclick = () => { localStorage.clear(); location.reload(); };
    document.getElementById('boot')?.appendChild(btn);
  }, 5000);
  setupOfflineDetection();
  updateOfflineBanner();
  try {
    await api._fetch('/api/health', { auth: false });
  } catch {
    const knownDevice = Vault.knownDeviceId();
    if (!knownDevice) { $('#bootMsg').textContent = 'Server nicht erreichbar.'; return; }
    state.isOffline = true;
  }
  const knownDevice = Vault.knownDeviceId();
  clearTimeout(resetTimeout);
  $('#boot').classList.add('hide');
  if (knownDevice) {
    renderLoginForKnownDevice(knownDevice, localStorage.getItem('sc:userName') || '');
  } else {
    renderAuthChoice();
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   AUTH
   ═══════════════════════════════════════════════════════════════════════ */
function showAuth(html) {
  $('#auth').innerHTML = html;
  $('#auth').classList.remove('hide');
  $('#app').classList.add('hide');
}
function renderAuthChoice() {
  showAuth(`
    <div id="authCard" class="card">
      <div class="logo"><div class="ic">🔐</div><h1>${t('appName')}</h1><p>${t('tagline')}</p></div>
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
  const phoneInput = $('#aPhone');
  if (phoneInput) {
    preparePhoneInput(phoneInput);
    const dial = guessDialCode();
    if (dial && !phoneInput.value) phoneInput.value = dial + ' ';
  }
}
function authErr(msg) { const e = $('#authErr'); e.textContent = '⚠️ ' + msg; e.classList.remove('hide'); }

async function authSubmit() {
  const btn = $('#authBtn'); btn.disabled = true;
  const name = $('#aUser').value.trim();
  try {
    if (!name) return authErr(t('fieldsRequired'));
    const phone = $('#aPhone').value.trim();
    const email = $('#aEmail').value.trim();
    if (!email) return authErr(t('emailRequired'));
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return authErr(t('emailInvalid'));
    btn.textContent = t('generatingKeys');
    const identity = await PreKeys.createStore();
    const platform = /Mobi|Android/i.test(navigator.userAgent) ? 'android' : (/iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'web');
    const data = await api.register({ name, phone: phone || undefined, email, deviceName: guessDeviceName(), platform, identity });
    await Vault.save(data.device.id, identity, { name, userId: data.user.id, token: data.token });
    Vault.rememberDevice(data.device.id, name);
    state.identity = identity;
    await afterAuth(data);
  } catch (e) {
    if (e.status === 428) renderPairingPrompt(name);
    else authErr(e.message);
  } finally { btn.disabled = false; }
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
      <div class="logo"><div class="ic">🔗</div><h1>${t('newDevice')}</h1><p>${t('appName')}</p></div>
      <div class="err" style="background:rgba(83,189,235,.1);border-color:rgba(83,189,235,.3);color:#a8dcf5">${t('pairHint')}</div>
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
      const platform = /Mobi|Android/i.test(navigator.userAgent) ? 'android' : (/iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'web');
      const data = await api.pairClaim({ code, deviceName: guessDeviceName(), platform, identity });
      await Vault.save(data.device.id, identity, { name: data.user.name, userId: data.user.id, token: data.token });
      Vault.rememberDevice(data.device.id, data.user.name);
      state.identity = identity;
      await afterAuth(data);
    } catch (e) {
      $('#pairErr').textContent = '⚠️ ' + e.message;
      $('#pairErr').classList.remove('hide');
    } finally { btn.disabled = false; btn.textContent = t('pair'); }
  };
}

function renderRecoveryPrompt() {
  showAuth(`
    <div class="card">
      <div class="logo"><div class="ic">📧</div><h1>Konto wiederherstellen</h1><p>${t('appName')}</p></div>
      <p style="color:var(--sub);font-size:14px;margin:0 0 16px">Wir schicken dir einen Code an deine bestätigte E-Mail-Adresse.</p>
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
      renderRecoveryCodeStep(email);
    } catch (e) {
      $('#recErr').textContent = '⚠️ ' + e.message; $('#recErr').classList.remove('hide');
    } finally { btn.disabled = false; }
  };
}

function renderRecoveryCodeStep(email) {
  showAuth(`
    <div class="card">
      <div class="logo"><div class="ic">📧</div><h1>Code eingeben</h1><p>${esc(email)}</p></div>
      <p style="color:var(--sub);font-size:14px;margin:0 0 16px">6-stelliger Code aus deinem Postfach (auch Spam prüfen).</p>
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
      if (!code || code.length !== 6) { $('#recCodeErr').textContent = 'Bitte 6-stelligen Code eingeben.'; $('#recCodeErr').classList.remove('hide'); return; }
      btn.textContent = t('generatingKeys');
      const identity = await PreKeys.createStore();
      const platform = /Mobi|Android/i.test(navigator.userAgent) ? 'android' : (/iPhone|iPad/i.test(navigator.userAgent) ? 'ios' : 'web');
      const data = await api.recoverVerify({ email, code, deviceName: guessDeviceName(), platform, identity });
      await Vault.save(data.device.id, identity, { name: data.user.name, userId: data.user.id, token: data.token });
      Vault.rememberDevice(data.device.id, data.user.name);
      state.identity = identity;
      await afterAuth(data);
    } catch (e) {
      $('#recCodeErr').textContent = '⚠️ ' + e.message; $('#recCodeErr').classList.remove('hide');
    } finally { btn.disabled = false; btn.textContent = 'Konto wiederherstellen'; }
  };
}

async function renderLoginForKnownDevice(deviceId, userName) {
  const vaultRec = Vault.load(deviceId);
  if (!vaultRec || !vaultRec.meta?.token) { Vault.forget(); renderAuthChoice(); return; }
  $('#boot').classList.add('hide');
  state.identity = await reconstructIdentityFromVault(vaultRec.data);
  api.token = vaultRec.meta.token;
  await LocalCache.unlock(deviceId);
  await LocalCache.load();
  /* FIX 1: Gespeicherte Ratchet-Sessions laden */
  const savedSessions = await SessionStore.loadAll();
  for (const [key, st] of savedSessions) state.sessions.set(key, st);
  await afterAuthOffline(deviceId, userName);
  fetch(API_BASE + '/api/me', { headers: { Authorization: 'Bearer ' + vaultRec.meta.token } })
    .then(async r => {
      if (r.status === 401) { Vault.forget(); location.reload(); return; }
      if (!r.ok) return;
      const me = await r.json();
      state.isOffline = false;
      updateOfflineBanner();
      await afterAuth({ token: vaultRec.meta.token, user: me.user, device: me.device });
    }).catch(() => {});
}

async function reconstructIdentityFromVault(data) {
  const log = [], step = msg => log.push(new Date().toISOString().slice(11,23) + ' — ' + msg);
  const bootMsgEl = document.getElementById('bootMsg');
  const setMsg = m => { if (bootMsgEl) bootMsgEl.textContent = m; };
  step('Start'); setMsg('IK wird importiert…');
  const timeoutId = setTimeout(() => { step('TIMEOUT'); showDiagPanel(log.join('\n')); }, 3000);
  try {
    const importDH   = jwk => crypto.subtle.importKey('jwk', jwk, { name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
    const importSign = jwk => crypto.subtle.importKey('jwk', jwk, { name:'ECDSA', namedCurve:'P-256' }, true, ['sign']);
    const pubOnly    = jwk => { const c = { ...jwk }; delete c.d; return c; };
    const IK  = { priv: await importDH(data.IK),   privJwk: data.IK,  pubJwk: pubOnly(data.IK) };
    const IKS = { priv: await importSign(data.IKS), privJwk: data.IKS, pubJwk: pubOnly(data.IKS) };
    const SPK = { priv: await importDH(data.SPK),   privJwk: data.SPK, pubJwk: pubOnly(data.SPK) };
    setMsg('OPKs werden importiert…');
    const opks = new Map();
    for (const [id, jwk] of data.opks) opks.set(id, { priv: await importDH(jwk), privJwk: jwk, pubJwk: pubOnly(jwk) });
    step('OK'); setMsg('Schlüssel importiert ✓');
    clearTimeout(timeoutId);
    return { IK, IKS, SPK, opks, opkSeq: opks.size, spkId: 1, consumed: 0, spkMeta: { spkId: 1, createdAt: Date.now(), sig: null } };
  } catch (e) { clearTimeout(timeoutId); step('FEHLER: ' + e.message); showDiagPanel(log.join('\n')); throw e; }
}

/* ═══════════════════════════════════════════════════════════════════════
   NACH ANMELDUNG
   ═══════════════════════════════════════════════════════════════════════ */
async function afterAuth(data) {
  state.me = data.user;
  state.device = data.device;
  state.monitor = new KT.Monitor();
  window.__app = appActions;
  if (!state.me.emailVerified) { showEmailVerifyPrompt(true); return; }
  await LocalCache.unlock(data.device.id);
  await LocalCache.load();
  /* FIX 1: Sessions aus IndexedDB laden falls noch nicht geschehen */
  if (state.sessions.size === 0) {
    const savedSessions = await SessionStore.loadAll();
    for (const [key, st] of savedSessions) state.sessions.set(key, st);
  }
  api.connect();
  wireSocketEvents();
  try { await window.StorageGuard?.requestPersistence?.(); } catch {}
  await loadBlockList();
  await refreshInbox();
  if ($('#app').classList.contains('hide')) {
    $('#auth').classList.add('hide');
    $('#app').classList.remove('hide');
    renderShell();
    go('chats');
    toast('Willkommen, ' + state.me.name + ' 🔐');
  } else {
    renderMain();
    updateOfflineBanner();
  }
}

function showEmailVerifyPrompt(blocking) {
  document.getElementById('verifySheet')?.remove();
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'verifySheet';
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 8px">E-Mail bestätigen</h3>
      <p style="color:var(--sub);margin:0 0 16px;font-size:14px">
        Wir haben einen 6-stelligen Code an ${esc(state.me.email)} geschickt.
        ${blocking ? 'Die Bestätigung ist erforderlich, um fortzufahren.' : ''}
      </p>
      <input id="verifyCodeInput" inputmode="numeric" maxlength="6" placeholder="000000"
        style="width:100%;box-sizing:border-box;font-size:24px;letter-spacing:8px;text-align:center;padding:14px;border-radius:10px;border:none;background:var(--panel2);color:var(--tx);margin-bottom:12px">
      <div id="verifyError" style="color:#f15c6d;font-size:13px;margin-bottom:12px;display:none"></div>
      <button class="btn" id="verifySubmitBtn" style="width:100%;margin-bottom:8px">Bestätigen</button>
      <button class="btn ghost" id="verifyResendBtn" style="width:100%${blocking ? '' : ';margin-bottom:8px'}">Code erneut senden</button>
      ${blocking ? '' : '<button class="btn ghost" id="verifyDismissBtn" style="width:100%">Später</button>'}
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
  document.getElementById('verifyCodeInput')?.focus();
  document.getElementById('verifySubmitBtn')?.addEventListener('click', submitEmailCode);
  document.getElementById('verifyResendBtn')?.addEventListener('click', resendEmailCode);
  document.getElementById('verifyDismissBtn')?.addEventListener('click', dismissEmailVerify);
}

async function submitEmailCode() {
  try {
    const input = document.getElementById('verifyCodeInput');
    const errEl = document.getElementById('verifyError');
    const code = input?.value.trim();
    if (!code || code.length !== 6) {
      if (errEl) { errEl.textContent = 'Bitte den 6-stelligen Code eingeben.'; errEl.style.display = 'block'; }
      return;
    }
    try {
      await api.verifyEmail(code);
      state.me.emailVerified = true;
      document.getElementById('verifySheet')?.remove();
      toast('✓ E-Mail bestätigt');
      if ($('#app').classList.contains('hide')) {
        $('#auth').classList.add('hide');
        $('#app').classList.remove('hide');
        renderShell(); go('chats');
        toast('Willkommen, ' + state.me.name + ' 🔐');
      }
    } catch (e) {
      const msg = e.message === 'Code falsch' ? 'Falscher Code — bitte prüfen.'
        : e.message === 'Code abgelaufen — neuen anfordern' ? 'Code abgelaufen — tipp auf "Code erneut senden".'
        : e.message;
      if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; }
    }
  } catch (outerErr) {
    alert('Fehler: ' + outerErr.message);
  }
}

async function resendEmailCode() {
  try { await api.resendVerification(); toast('📧 Neuer Code verschickt'); }
  catch (e) { toast('⚠️ ' + e.message); }
}

function dismissEmailVerify() { document.getElementById('verifySheet')?.remove(); }

async function afterAuthOffline(deviceId, userName) {
  state.me = { id: null, name: userName };
  state.device = { id: deviceId };
  state.isOffline = true;
  await LocalCache.load();
  $('#auth').classList.add('hide');
  $('#app').classList.remove('hide');
  renderShell(); go('chats');
  updateOfflineBanner();
  toast('📵 Offline — zeige gespeicherten Verlauf.', 3500);
}

function wireSocketEvents() {
  if (wireSocketEvents._wired) return;
  wireSocketEvents._wired = true;
  api.on('envelope', onIncomingEnvelope);
  api.on('presence', onPresence);
  window.Call = Call;
  if (!window.__initCallUI) {
    const s = document.createElement('script');
    s.src = '/call-ui.js';
    s.onload = () => { if (window.__initCallUI) window.__initCallUI(api); };
    document.head.appendChild(s);
  } else { window.__initCallUI(api); }
  api.on('device-added', d => toast('Neues Gerät verbunden: ' + (d.device?.name || '')));
  api.on('device-revoked', () => { toast('Dieses Gerät wurde entfernt.'); setTimeout(() => { Vault.forget(); location.reload(); }, 1500); });
  api.on('contact-joined', () => toast('Ein Kontakt nutzt jetzt auch SecureChat 👋'));
  api.on('need-prekeys', () => refillPrekeys().catch(() => {}));
  api.on('connected', () => { toast('🟢 Verbunden', 1500); state.isOffline = false; updateOfflineBanner(); flushOutbox(); });
  api.on('disconnected', () => toast('Verbindung unterbrochen…', 1800));
}

async function refillPrekeys() {
  const more = [];
  for (let i = 0; i < 10; i++) {
    const k = await P.genDH(); const id = ++state.identity.opkSeq;
    state.identity.opks.set(id, k); more.push({ opkId: id, pub: k.pubJwk });
  }
  await api.uploadPrekeys({ opks: more });
}

/* ═══════════════════════════════════════════════════════════════════════
   POSTEINGANG
   ═══════════════════════════════════════════════════════════════════════ */
async function refreshInbox() {
  const { envelopes } = await api.inbox();
  const toAck = [];
  for (const env of envelopes) { await handleEnvelope(env, false); toAck.push(env.id); }
  if (toAck.length) await api.ack(toAck);
  renderMain();
}

async function onIncomingEnvelope(env) {
  await handleEnvelope(env, true);
  const convId = env.convId || ('dm_' + [state.me?.id, env.senderId].filter(Boolean).sort().join('_'));
  if (state.view === 'chat' && state.activeConv?.convId === convId) renderChatMessages();
  else renderMain();
}

async function handleEnvelope(env, live) {
  const convId = env.convId || ('dm_' + [state.me.id, env.senderId].filter(Boolean).sort().join('_'));
  let plaintext = '[verschlüsselt]';
  try {
    plaintext = env.sealed ? await openSealed(env) : await openRatchet(env);
  } catch (e) {
    console.warn('Entschlüsselung fehlgeschlagen:', e.message);
    plaintext = '⚠️ [' + e.name + '] ' + e.message + ' | header:' + JSON.stringify(env.header || null) + ' | sealed:' + !!env.sealed;
  }

  const conv = state.convs.get(convId) || { convId, peerId: env.senderId, unread: 0 };

  /* FIX 2b: Name sofort aus User-Liste holen */
  if (!conv.name && env.senderName) conv.name = env.senderName;
  if (!conv.name && env.senderId) {
    try {
      const allUsers = await api.listUsers();
      const found = (allUsers.users || []).find(u => u.id === env.senderId);
      if (found?.name) conv.name = found.name;
    } catch {}
  }
  if (!conv.name && env.senderId) {
    fetch(API_BASE + '/api/user/' + env.senderId, { headers: { Authorization: 'Bearer ' + api.token } })
      .then(r => r.ok ? r.json() : null).then(u => { if (u?.user?.name) { conv.name = u.user.name; renderMain(); } }).catch(() => {});
  }

  if (!state.messages.has(convId)) state.messages.set(convId, []);
  state.messages.get(convId).push({
    id: env.id,
    from: conv.name || env.senderName || env.senderId || '(versiegelt)',
    text: plaintext, ts: env.sentAt, mine: false, sealed: !!env.sealed
  });
  conv.lastMsg = { text: plaintext, ts: env.sentAt };
  conv.unread = (conv.unread || 0) + 1;
  state.convs.set(convId, conv);
  LocalCache.scheduleSave();
  if (live) api.ackViaSocket([env.id]);
}

/* FIX 1: openRatchet speichert Session nach Entschlüsselung */
async function openRatchet(env) {
  try {
    const key = sk(env.senderId, env.senderDeviceId);
    let st = state.sessions.get(key);
    if (!st) st = await ensureReceiverSession(env);
    const { x3dh, ...ratchetHeader } = env.header || {};
    /* AAD muss identisch mit dem Sender sein.
       Bei Sealed Sender ist senderId null — aus convId ableiten */
    let senderId = env.senderId;
    if (!senderId && env.convId && env.convId.startsWith('dm_')) {
      const parts = env.convId.replace('dm_', '').split('_');
      senderId = parts.find(p => p !== state.me.id) || '';
    }
    const assoc = `v1|${senderId}|${env.convId}`;
    const buf = await Ratchet.decrypt(st, { header: ratchetHeader, ct: ub64(env.ciphertext) }, assoc);
    await SessionStore.save(key, st);
    return td.decode(buf);
  } catch(e) {
    const info = 'hadSess:' + !!state.sessions.get(sk(env.senderId, env.senderDeviceId))
      + ' hdr:' + JSON.stringify(env.header).slice(0,80)
      + ' err:[' + (e?.name||'?') + ']' + (e?.message||'leer')
      + ' stack:' + String(e?.stack||'').slice(0,120);
    throw new Error(info);
  }
}

async function openSealed(env) {
  const raw = ub64(env.ciphertext);
  const sep = raw.indexOf(0);
  const ephJwk = JSON.parse(td.decode(raw.subarray(0, sep)));
  const ct = raw.subarray(sep + 1);
  const eph = await crypto.subtle.importKey('jwk', ephJwk, { name:'ECDH', namedCurve:'P-256' }, true, []);
  const shared = await crypto.subtle.deriveBits({ name:'ECDH', public: eph }, state.identity.IK.priv, 256);
  const out = await P.hkdf(shared, null, 'SecureChat-SealedSender-v1', 44);
  const key = await crypto.subtle.importKey('raw', out.slice(0, 32), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv: out.slice(32, 44) }, key, ct);
  const inner = JSON.parse(td.decode(pt));
  return `(von ${esc(inner.cert.senderName)}) ` + (inner.plaintext || '[Medien]');
}

/* FIX 2: Presence — beim Chat-Öffnen Online-Status aktiv abfragen */
function onPresence(msg) {
  for (const conv of state.convs.values()) {
    if (conv.peerId === msg.userId) conv.online = msg.online;
  }
  if (state.view === 'chat' && state.activeConv?.peerId === msg.userId) renderChatHeader();
  if (state.view === 'list') renderMain();
}

async function fetchPresence(peerId) {
  try {
    const users = await api.listUsers();
    const u = (users.users || []).find(u => u.id === peerId);
    if (u) {
      const conv = [...state.convs.values()].find(c => c.peerId === peerId);
      if (conv) { conv.online = !!u.online; }
      renderChatHeader();
    }
  } catch {}
}

async function loadBlockList() {
  try { const { blocked } = await api.blockedList(); state.blocked = new Set(blocked); } catch {}
}

/* ═══════════════════════════════════════════════════════════════════════
   SHELL
   ═══════════════════════════════════════════════════════════════════════ */
function renderShell() {
  $('#app').innerHTML = `
    <div class="topbar"><h1>SecureChat</h1>
      <div class="topicons">
        <button class="iconbtn" onclick="window.__app.openCamera()">📷</button>
        <button class="iconbtn" onclick="window.__app.mainMenu(event)">⋮</button>
      </div>
    </div>
    <div class="searchwrap"><div class="search"><span class="ic">🔍</span>
      <input id="searchInput" placeholder="Suchen" oninput="window.__app.onSearch(this.value)"></div></div>
    <div class="pillbar" id="pillbar"></div>
    <div id="main"></div>
    <div id="navbar"></div>`;
  window.__app = appActions;
  renderPills(); renderNav(); renderMain();
}

const PILLS = [['all','Alle'],['unread','Ungelesen'],['favorites','Favoriten'],['groups','Gruppen']];
let activePill = 'all';
function renderPills() {
  $('#pillbar').innerHTML = PILLS.map(([id, label]) =>
    `<button class="pill ${activePill === id ? 'on' : ''}" onclick="window.__app.setPill('${id}')">${label}</button>`
  ).join('') + `<button class="pill plus" onclick="window.__app.newChat()">+</button>`;
}
function renderNav() {
  const totalUnread = [...state.convs.values()].reduce((a, c) => a + (c.unread || 0), 0);
  const tabs = [['chats','💬','Chats',totalUnread],['updates','📸','Aktuelles',0],['communities','👥','Communitys',0],['calls','📞','Anrufe',0]];
  $('#navbar').innerHTML = tabs.map(([id, ic, lb, bdg]) =>
    `<button class="${state.tab === id ? 'on' : ''}" onclick="window.__app.go('${id}')">
      <span class="navic">${ic}</span><span class="navlb">${lb}</span>${bdg ? `<span class="navbdg"></span>` : ''}
    </button>`).join('');
}
function go(tab) { state.tab = tab; state.view = 'list'; renderNav(); renderMain(); }
function renderMain() {
  if (state.view !== 'list') return;
  const main = $('#main'); if (!main) return;
  if (state.tab !== 'chats') { main.innerHTML = `<div class="empty"><div class="ic">🚧</div><div>Noch nicht verfügbar</div></div>`; return; }
  let convs = [...state.convs.values()];
  if (activePill === 'unread') convs = convs.filter(c => (c.unread || 0) > 0);
  if (activePill === 'groups') convs = convs.filter(c => c.isGroup);
  if (state.search) { const q = state.search.toLowerCase(); convs = convs.filter(c => (c.name || c.peerId || '').toLowerCase().includes(q)); }
  convs.sort((a, b) => (b.lastMsg?.ts || 0) - (a.lastMsg?.ts || 0));
  main.innerHTML = `
    <div class="scroll" style="height:100%;position:relative">
      ${convs.length ? convs.map((c, i) => convRow(c, i)).join('') : `<div class="empty"><div class="ic">💬</div><div>Noch keine Chats.<br>Tippe auf + um zu starten.</div></div>`}
      <div class="fab" onclick="window.__app.newChat()">💬</div>
    </div>`;
  window.__conv = convs;
}
function convRow(c, i) {
  const name = c.name || c.peerId || 'Unbekannt';
  const avatar = c.avatarUrl ? `<img src="${c.avatarUrl}">` : (name[0] || '?').toUpperCase();
  const unread = c.unread || 0;
  const preview = c.lastMsg ? esc(c.lastMsg.text).slice(0, 60) : 'Noch keine Nachrichten';
  return `
    <div class="row" onclick="window.__app.openConv(${i})">
      <div class="av">${avatar}${c.isGroup ? '' : `<div class="dot ${c.online ? 'online' : 'offline'}"></div>`}</div>
      <div class="meta">
        <div class="l1"><span class="nm">${esc(name)}</span><span class="tm ${unread ? 'un' : ''}">${c.lastMsg ? time(c.lastMsg.ts) : ''}</span></div>
        <div class="l2"><span class="pv">${preview}</span>${unread ? `<span class="unread">${unread}</span>` : ''}</div>
      </div>
    </div>`;
}

/* ═══════════════════════════════════════════════════════════════════════
   AKTIONEN
   ═══════════════════════════════════════════════════════════════════════ */
const appActions = {
  setPill(id) { activePill = id; renderPills(); renderMain(); },
  onSearch(v) { state.search = v; renderMain(); },
  go(tab) { go(tab); },
  openConv(i) { openChat(window.__conv[i]); },
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
  startChatWith(userId, userName) { startChatWith(userId, userName); },
  chatMenu(e) { chatMenu(e); },
  toggleBlock() { toggleBlock(); },
  reportUser() { reportUser(); },
  submitReport() { submitReport(); },
  attachSheet() { attachSheet(); },
  pickMedia(accept, kind) { pickMedia(accept, kind); },
  loadMedia(msgId) {
    for (const list of state.messages.values()) {
      const m = list.find(x => x.id === msgId);
      if (m) { const media = m.media || parseIncomingMedia(m.text); if (media) downloadAndShowMedia(msgId, media.ref, media.kind); break; }
    }
  }
};

/* ═══════════════════════════════════════════════════════════════════════
   X3DH — FIX 1: Session nach Aufbau persistieren
   ═══════════════════════════════════════════════════════════════════════ */
async function ensureSessions(peerId) {
  const { bundles } = await api.fetchBundle(peerId);
  if (!bundles?.length) throw new Error('Kein aktives Gerät für diesen Nutzer gefunden');
  const missing = bundles.filter(b => !state.sessions.has(sk(peerId, b.deviceId)));
  for (const bundle of missing) {
    const verify = await PreKeys.verifyBundle(bundle);
    if (!verify.ok) { console.warn('Bundle-Signatur ungültig', bundle.deviceId, verify.reason); continue; }
    const { SK, EK } = await X3DH.initiator(state.identity.IK, bundle);
    const st = await Ratchet.initSender(SK, bundle.spk);
    st.usedOpkId = bundle.opkId;
    st.ephemeral = EK;
    state.sessions.set(sk(peerId, bundle.deviceId), st);
    /* FIX 1: Neue Session sofort speichern */
    await SessionStore.save(sk(peerId, bundle.deviceId), st);
  }
  return bundles;
}

async function ensureReceiverSession(env) {
  const key = sk(env.senderId, env.senderDeviceId);
  if (state.sessions.has(key)) return state.sessions.get(key);
  if (!env.header?.x3dh) throw new Error('Kein X3DH-Header — Sitzung nicht rekonstruierbar');
  const { senderIK, senderEK, opkId } = env.header.x3dh;
  const usedOpk = opkId ? state.identity.opks.get(opkId) : null;
  const SK = await X3DH.responder(state.identity.IK, state.identity.SPK, usedOpk, senderIK, senderEK);
  const st = Ratchet.initReceiver(SK, state.identity.SPK);
  state.sessions.set(key, st);
  if (usedOpk) state.identity.opks.delete(opkId);
  /* FIX 1: Neue Empfänger-Session sofort speichern */
  await SessionStore.save(key, st);
  return st;
}

/* ═══════════════════════════════════════════════════════════════════════
   SENDEN — FIX 1: Session nach dem Senden persistieren
   ═══════════════════════════════════════════════════════════════════════ */
async function sendMessage(peerId, convId, plaintext) {
  const bundles = await ensureSessions(peerId);
  const perDevice = [];
  for (const bundle of bundles) {
    const key = sk(peerId, bundle.deviceId);
    const st = state.sessions.get(key);
    if (!st) continue;
    const isFirst = st.Ns === 0 && !!st.ephemeral;
    const env = await Ratchet.encrypt(st, te.encode(plaintext), `v1|${state.me.id}|${convId}`);
    const header = isFirst
      ? { ...env.header, x3dh: { senderIK: state.identity.IK.pubJwk, senderEK: st.ephemeral.pubJwk, opkId: st.usedOpkId } }
      : env.header;
    perDevice.push({ deviceId: bundle.deviceId, header, ciphertext: b64(env.ct) });
    /* FIX 1: Session nach Verschlüsselung persistieren */
    await SessionStore.save(key, st);
  }
  if (!perDevice.length) throw new Error('Keine gültige Sitzung aufbaubar');
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
  input.value = ''; input.style.height = 'auto';
  const { peerId, convId } = state.activeConv;
  if (state.isOffline) { queueOffline(peerId, convId, text); return; }
  try {
    await sendMessage(peerId, convId, text);
    renderChatMessages();
  } catch (e) {
    if (e.status === undefined) {
      state.isOffline = true; updateOfflineBanner(); queueOffline(peerId, convId, text);
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
   CHAT-FENSTER — FIX 2: Presence beim Öffnen aktiv abfragen
   ═══════════════════════════════════════════════════════════════════════ */
function openChat(c) {
  state.view = 'chat';
  state.activeConv = { peerId: c.peerId, convId: c.convId, name: c.name || c.peerId };
  if (c.unread) c.unread = 0;
  const overlay = document.createElement('div');
  overlay.className = 'chatview'; overlay.id = 'chatOverlay';
  overlay.innerHTML = `
    <div class="chatbar">
      <button class="iconbtn" onclick="window.__app.closeChat()">←</button>
      <div class="av" style="width:38px;height:38px;font-size:16px">${(c.name || '?')[0].toUpperCase()}</div>
      <div class="name">
        <div class="nm">${esc(c.name || c.peerId)}</div>
        <div class="st" id="chatStatus">${c.online ? 'online' : 'Wird geladen…'}</div>
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
  /* FIX 2: Online-Status sofort aktiv vom Server holen */
  fetchPresence(c.peerId);
}

function closeChat() {
  document.getElementById('chatOverlay')?.remove();
  state.view = 'list'; state.activeConv = null; renderMain();
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
  const rows = ['<div class="encnote">🔒 Ende-zu-Ende-verschlüsselt.</div>'];
  for (const m of msgs) {
    const d = day(m.ts);
    if (d !== lastDay) { rows.push(`<div class="daysep"><span>${d}</span></div>`); lastDay = d; }
    const incomingMedia = !m.media && !m.mine ? parseIncomingMedia(m.text) : null;
    const media = m.media || incomingMedia;
    let content;
    if (media) {
      if (m.mediaUrl) {
        content = media.kind === 'image' ? `<div class="media"><img src="${m.mediaUrl}"></div>`
          : media.kind === 'video' ? `<div class="media"><video src="${m.mediaUrl}" controls></video></div>`
          : `<div class="filemsg">📄 <a href="${m.mediaUrl}" download style="color:inherit">${esc(media.name || 'Datei')}</a></div>`;
      } else {
        const icon = media.kind === 'image' ? '🖼️' : media.kind === 'video' ? '🎬' : '📄';
        content = `<div class="filemsg" style="cursor:pointer" onclick="window.__app.loadMedia('${m.id}')">${icon} <span>${media.kind === 'image' ? 'Foto' : media.kind === 'video' ? 'Video' : (media.name || 'Datei')} — antippen zum Laden</span></div>`;
      }
    } else { content = `<div class="tx">${esc(m.text)}</div>`; }
    rows.push(`
      <div class="msgrow ${m.mine ? 'mine' : ''}">
        <div class="bub" style="${m.pending ? 'opacity:.65' : ''}">
          ${!m.mine && m.from ? `<div style="font-size:11px;color:var(--acc);margin-bottom:2px">${esc(m.from)}</div>` : ''}
          ${content}
          <div class="ft"><span class="tm">${time(m.ts)}</span>
            ${m.mine ? (m.pending ? `<span class="ck">🕐</span>` : `<span class="ck">✓✓</span>`) : ''}
          </div>
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
  try { ({ users } = await api.listUsers()); } catch (e) { toast('⚠️ ' + e.message); return; }
  const sheet = document.createElement('div');
  sheet.className = 'sheet'; sheet.id = 'newChatSheet';
  sheet.onclick = e => { if (e.target === sheet) sheet.remove(); };
  sheet.innerHTML = `
    <div class="sheetbox">
      <div class="grabber"></div>
      <h3 style="margin:0 0 12px">Neuer Chat</h3>
      ${users.length ? users.map(u => `
        <div class="row" style="padding:8px 0" onclick="window.__app.startChatWith('${u.id}', '${esc(u.name || '')}')">
          <div class="av">${esc((u.name || '?')[0].toUpperCase())}<div class="dot ${u.online ? 'online' : 'offline'}"></div></div>
          <div class="meta" style="border-bottom:none"><div class="l1"><span class="nm">${esc(u.name)}</span></div></div>
        </div>`).join('') : `<div class="empty" style="height:auto;padding:24px"><div class="ic">👤</div><div>Noch keine anderen Nutzer</div></div>`}
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

function startChatWith(userId, userName) {
  document.getElementById('newChatSheet')?.remove();
  const convId = 'dm_' + [state.me.id, userId].sort().join('_');
  let conv = state.convs.get(convId);
  if (!conv) { conv = { convId, peerId: userId, name: userName || userId, unread: 0 }; state.convs.set(convId, conv); }
  else if (!conv.name || conv.name === conv.peerId) conv.name = userName || conv.name;
  openChat(conv);
}

function openMainMenu() {
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
  Vault.forget(); location.reload();
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
      <p style="color:var(--sub);margin:0 0 16px;font-size:14px">Nicht rückgängig zu machen. Tipp zur Bestätigung deinen Namen <strong>${esc(state.me.name)}</strong> ein.</p>
      <input id="deleteAccountConfirm" type="text" placeholder="${esc(state.me.name)}" autocomplete="off"
        style="width:100%;box-sizing:border-box;font-size:16px;padding:14px;border-radius:10px;border:none;background:var(--panel2);color:var(--tx);margin-bottom:12px">
      <div id="deleteAccountError" style="color:#f15c6d;font-size:13px;margin-bottom:12px;display:none"></div>
      <button class="btn" style="width:100%;margin-bottom:8px;background:#f15c6d" onclick="window.__app.confirmDeleteAccount()">Konto endgültig löschen</button>
      <button class="btn ghost" style="width:100%" onclick="document.getElementById('deleteAccountSheet').remove()">Abbrechen</button>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

async function confirmDeleteAccount() {
  const input = document.getElementById('deleteAccountConfirm');
  const errEl = document.getElementById('deleteAccountError');
  if (input?.value.trim() !== state.me.name) { errEl.textContent = 'Name stimmt nicht überein.'; errEl.style.display = 'block'; return; }
  try { await api.deleteAccount(); Vault.forget(); location.reload(); }
  catch (e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
}

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
          <span class="nm" style="color:${isBlocked ? 'var(--acc2)' : 'var(--dan)'}">${isBlocked ? 'Entsperren' : 'Blockieren'}</span>
        </div></div>
      </div>
    </div>`;
  document.getElementById('overlays').appendChild(sheet);
}

async function toggleBlock() {
  document.getElementById('chatMenuSheet')?.remove();
  const peerId = state.activeConv?.peerId; if (!peerId) return;
  try {
    if (state.blocked.has(peerId)) { await api.unblock(peerId); state.blocked.delete(peerId); toast('Entsperrt'); }
    else { await api.block(peerId); state.blocked.add(peerId); toast('Blockiert'); }
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
      <label>Grund</label>
      <select class="in" id="repReason">
        <option value="spam">Spam</option><option value="harassment">Belästigung</option>
        <option value="illegal">Illegaler Inhalt</option><option value="csam">Gefährdung Minderjähriger</option>
        <option value="other">Anderer Grund</option>
      </select>
      <label>Zusätzliche Angaben (optional)</label>
      <textarea class="in" id="repNote" rows="3" placeholder="Kontext…"></textarea>
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
  try { await api.report({ reportedId: peerId, convId: state.activeConv?.convId, reason, note }); toast('Gemeldet 🚩'); }
  catch (e) { toast('⚠️ ' + e.message); }
}

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
  input.onchange = async () => { const file = input.files?.[0]; if (!file) return; await sendMediaMessage(file, kind); };
  input.click();
}

async function sendMediaMessage(file, kind) {
  if (!state.activeConv) return;
  if (!window.MediaStorage || !window.MEDIA_CONFIG?.uploadUrl) { toast('⚠️ Kein Medienspeicher konfiguriert'); return; }
  toast('📎 Wird hochgeladen…', 4000);
  try {
    let toUpload = file;
    if (kind === 'image') { try { toUpload = await window.MediaStorage.shrinkImage(file); } catch {} }
    const uploaded = await window.MediaStorage.uploadMedia(toUpload, { uploadUrl: window.MEDIA_CONFIG.uploadUrl, kind });
    const ref = window.MediaStorage.mediaReference(uploaded);
    const result = await sendMessage(state.activeConv.peerId, state.activeConv.convId, JSON.stringify({ __media: ref, kind }));
    const conv = state.convs.get(state.activeConv.convId);
    if (conv) conv.lastMsg = { text: kind === 'image' ? '📷 Foto' : kind === 'video' ? '🎬 Video' : '📄 ' + file.name, ts: result.sentAt };
    const msgs = state.messages.get(state.activeConv.convId) || [];
    const last = msgs[msgs.length - 1];
    if (last) { last.media = { ref, kind, name: file.name }; last.text = ''; }
    renderChatMessages();
  } catch (e) { toast('⚠️ Upload fehlgeschlagen: ' + e.message); }
}

function parseIncomingMedia(text) {
  try { const obj = JSON.parse(text); if (obj && obj.__media) return { ref: obj.__media, kind: obj.kind }; } catch {}
  return null;
}

async function downloadAndShowMedia(msgId, ref, kind) {
  if (!window.MediaStorage || !window.MEDIA_CONFIG?.downloadUrl) { toast('⚠️ Kein Medienspeicher'); return; }
  toast('⬇️ Wird geladen…', 3000);
  try {
    const blob = await window.MediaStorage.downloadMedia(ref, { downloadUrl: window.MEDIA_CONFIG.downloadUrl });
    const url = URL.createObjectURL(blob);
    for (const list of state.messages.values()) { const m = list.find(x => x.id === msgId); if (m) { m.mediaUrl = url; break; } }
    renderChatMessages();
  } catch (e) { toast('⚠️ Laden fehlgeschlagen: ' + e.message); }
}

export { state, Vault, reconstructIdentityFromVault, sk, boot,
  authSubmit, renderAuthChoice, renderPills, renderNav,
  renderMain, go, convRow, handleEnvelope, api,
  ensureSessions, ensureReceiverSession, sendMessage, openRatchet,
  openChat, closeChat, startChatWith, renderChatMessages,
  toggleBlock, submitReport, sendMediaMessage, parseIncomingMedia,
  downloadAndShowMedia, sendCurrentMessage, queueOffline, flushOutbox,
  setupOfflineDetection, LocalCache, afterAuthOffline, afterAuth };

if (typeof document !== 'undefined' && document.getElementById('boot')) { boot(); }
