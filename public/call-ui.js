/* ═══════════════════════════════════════════════════════════════════════
   CALL-UI — Anruf-Oberfläche (Klingeln, aktiver Anruf, Steuerelemente)
   ─────────────────────────────────────────────────────────────────────
   Reines Overlay über die gesamte App, unabhängig vom restlichen
   Chat-UI-Code — hört auf Call.subscribe() und zeigt/versteckt sich
   selbst je nach Anrufzustand. Einzige Voraussetzung: ein Element mit
   id="callOverlay" muss im HTML vorhanden sein (leer, wird hier befüllt).
   ═══════════════════════════════════════════════════════════════════════ */
/* call-ui.js — kein ES-Modul-Import, Call kommt von app.js */

let overlayEl = null;
let remoteVideoEl = null;
let localVideoEl = null;
let ringtoneAudio = null;

function el(html) {
  const div = document.createElement('div');
  div.innerHTML = html.trim();
  return div.firstChild;
}

function ensureOverlay() {
  overlayEl = document.getElementById('callOverlay');
  if (!overlayEl) {
    overlayEl = document.createElement('div');
    overlayEl.id = 'callOverlay';
    document.body.appendChild(overlayEl);
  }
}

/* Einfacher Klingelton per WebAudio, kein externes Audiofile nötig —
   zwei abwechselnde Töne, wie ein klassisches Telefonklingeln. */
function startRingtone() {
  stopRingtone();
  const ctx = new (window.AudioContext || window.webkitAudioContext)();
  const gain = ctx.createGain();
  gain.gain.value = 0.15;
  gain.connect(ctx.destination);
  let playing = true;
  function beep() {
    if (!playing) return;
    const osc = ctx.createOscillator();
    osc.frequency.value = 880;
    osc.connect(gain);
    osc.start();
    osc.stop(ctx.currentTime + 0.4);
    setTimeout(beep, 1200);
  }
  beep();
  ringtoneAudio = { stop: () => { playing = false; ctx.close(); } };
}
function stopRingtone() {
  if (ringtoneAudio) { ringtoneAudio.stop(); ringtoneAudio = null; }
}

function render(state) {
  ensureOverlay();
  stopRingtone();

  if (state.state === 'idle') {
    overlayEl.innerHTML = '';
    overlayEl.style.display = 'none';
    if (state.reason) showEndReasonToast(state.reason);
    return;
  }

  overlayEl.style.display = 'flex';

  if (state.state === 'ringing') {
    renderRinging(state.call);
    startRingtone();
  if (state.state === 'calling') {
    renderCalling(state.call);
    if (state.localStream && localVideoEl) localVideoEl.srcObject = state.localStream;
  } else if (state.state === 'connecting') {
    renderConnecting(state.call);
    if (state.localStream && localVideoEl) localVideoEl.srcObject = state.localStream;
  } else if (state.state === 'connected') {
    renderConnected(state.call, state.remoteStream);
    if (state.localStream && localVideoEl) localVideoEl.srcObject = state.localStream;
  } else if (state.state === 'error') {
    renderError(state.reason, state.message);
  }
}

function showEndReasonToast(reason) {
  const messages = {
    'no-answer': 'Keine Antwort',
    'declined': 'Anruf abgelehnt',
    'peer-busy': 'Person ist bereits in einem Gespräch',
    'peer-ended': 'Anruf beendet',
    'unavailable': 'Person ist nicht erreichbar',
    'ended': 'Anruf beendet'
  };
  const text = messages[reason] || 'Anruf beendet';
  const toastEl = el(`<div class="call-toast">${text}</div>`);
  document.body.appendChild(toastEl);
  setTimeout(() => toastEl.remove(), 2500);
}

function renderRinging(call) {
  overlayEl.innerHTML = '';
  overlayEl.appendChild(el(`
    <div class="call-screen call-incoming">
      <div class="call-avatar">${(call.peerName || '?')[0].toUpperCase()}</div>
      <div class="call-peername">${escapeHtml(call.peerName)}</div>
      <div class="call-status">${call.kind === 'video' ? 'Video-Anruf' : 'Anruf'} …</div>
      <div class="call-actions call-actions-incoming">
        <button class="call-btn call-btn-reject" id="callRejectBtn" aria-label="Ablehnen">✕</button>
        <button class="call-btn call-btn-accept" id="callAcceptBtn" aria-label="Annehmen">✓</button>
      </div>
    </div>
  `));
  document.getElementById('callAcceptBtn').onclick = () => Call.accept();
  document.getElementById('callRejectBtn').onclick = () => Call.reject();
}

function renderCalling(call) {
  overlayEl.innerHTML = '';
  overlayEl.appendChild(el(`
    <div class="call-screen">
      <div class="call-avatar">${(call.peerName || '?')[0].toUpperCase()}</div>
      <div class="call-peername">${escapeHtml(call.peerName)}</div>
      <div class="call-status">Klingelt …</div>
      ${call.kind === 'video' ? '<video id="callLocalVideo" class="call-local-preview" autoplay muted playsinline></video>' : ''}
      <div class="call-actions">
        <button class="call-btn call-btn-end" id="callEndBtn" aria-label="Auflegen">✕</button>
      </div>
    </div>
  `));
  document.getElementById('callEndBtn').onclick = () => Call.endCall();
  localVideoEl = document.getElementById('callLocalVideo');
}

function renderConnecting(call) {
  overlayEl.innerHTML = '';
  overlayEl.appendChild(el(`
    <div class="call-screen">
      <div class="call-avatar">${(call.peerName || '?')[0].toUpperCase()}</div>
      <div class="call-peername">${escapeHtml(call.peerName)}</div>
      <div class="call-status">Verbinde …</div>
      ${call.kind === 'video' ? '<video id="callLocalVideo" class="call-local-preview" autoplay muted playsinline></video>' : ''}
      <div class="call-actions">
        <button class="call-btn call-btn-end" id="callEndBtn" aria-label="Auflegen">✕</button>
      </div>
    </div>
  `));
  document.getElementById('callEndBtn').onclick = () => Call.endCall();
  localVideoEl = document.getElementById('callLocalVideo');
}

function renderConnected(call, remoteStream) {
  const isVideo = call.kind === 'video';
  overlayEl.innerHTML = '';
  overlayEl.appendChild(el(`
    <div class="call-screen call-connected">
      ${isVideo
        ? '<video id="callRemoteVideo" class="call-remote-video" autoplay playsinline></video>'
        : `<div class="call-avatar call-avatar-large">${(call.peerName || '?')[0].toUpperCase()}</div>`}
      <div class="call-peername ${isVideo ? 'call-peername-overlay' : ''}">${escapeHtml(call.peerName)}</div>
      <div class="call-status call-timer" id="callTimer">00:00</div>
      ${isVideo ? '<video id="callLocalVideo" class="call-local-preview call-local-preview-small" autoplay muted playsinline></video>' : ''}
      <div class="call-actions call-actions-connected">
        <button class="call-btn call-btn-secondary" id="callMuteBtn" aria-label="Stummschalten">🎤</button>
        ${isVideo ? '<button class="call-btn call-btn-secondary" id="callCamBtn" aria-label="Kamera">📷</button>' : ''}
        <button class="call-btn call-btn-end" id="callEndBtn" aria-label="Auflegen">✕</button>
      </div>
    </div>
  `));

  remoteVideoEl = document.getElementById('callRemoteVideo');
  localVideoEl = document.getElementById('callLocalVideo');
  if (remoteVideoEl && remoteStream) remoteVideoEl.srcObject = remoteStream;

  document.getElementById('callEndBtn').onclick = () => Call.endCall();
  document.getElementById('callMuteBtn').onclick = (e) => {
    const muted = Call.toggleMute();
    e.target.textContent = muted ? '🔇' : '🎤';
    e.target.classList.toggle('call-btn-active', muted);
  };
  const camBtn = document.getElementById('callCamBtn');
  if (camBtn) camBtn.onclick = (e) => {
    const camOff = Call.toggleCamera();
    e.target.textContent = camOff ? '🚫' : '📷';
    e.target.classList.toggle('call-btn-active', camOff);
  };

  startCallTimer();
}

let timerInterval = null;
function startCallTimer() {
  clearInterval(timerInterval);
  const startedAt = Date.now();
  timerInterval = setInterval(() => {
    const timerEl = document.getElementById('callTimer');
    if (!timerEl) { clearInterval(timerInterval); return; }
    const secs = Math.floor((Date.now() - startedAt) / 1000);
    const mm = String(Math.floor(secs / 60)).padStart(2, '0');
    const ss = String(secs % 60).padStart(2, '0');
    timerEl.textContent = `${mm}:${ss}`;
  }, 1000);
}

function renderError(reason, message) {
  overlayEl.innerHTML = '';
  const text = reason === 'no-media'
    ? 'Kein Zugriff auf Kamera/Mikrofon. Bitte in den Browser-Einstellungen erlauben.'
    : 'Verbindung fehlgeschlagen.';
  overlayEl.appendChild(el(`
    <div class="call-screen">
      <div class="call-status call-error">${text}</div>
      <div class="call-actions">
        <button class="call-btn call-btn-end" id="callErrOkBtn">Schließen</button>
      </div>
    </div>
  `));
  document.getElementById('callErrOkBtn').onclick = () => { overlayEl.innerHTML = ''; overlayEl.style.display = 'none'; };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

/* ── Öffentlich: einmalig beim App-Start aufrufen ── */
function initCallUI(api) {
  Call.wire(api);
  Call.subscribe(render);
  injectStyles();
}

function injectStyles() {
  if (document.getElementById('call-ui-styles')) return;
  const style = document.createElement('style');
  style.id = 'call-ui-styles';
  style.textContent = `
    #callOverlay{position:fixed;inset:0;z-index:500;display:none;background:var(--bg,#0b141a);
      flex-direction:column;align-items:center;justify-content:center;color:var(--tx,#e9edef)}
    .call-screen{display:flex;flex-direction:column;align-items:center;justify-content:center;
      width:100%;height:100%;position:relative;gap:14px}
    .call-avatar{width:96px;height:96px;border-radius:50%;background:var(--panel2,#182229);
      display:flex;align-items:center;justify-content:center;font-size:38px;font-weight:600;
      color:var(--accent,#25d366)}
    .call-avatar-large{width:140px;height:140px;font-size:56px}
    .call-peername{font-size:22px;font-weight:600}
    .call-peername-overlay{position:absolute;top:40px;left:0;right:0;text-align:center;
      text-shadow:0 2px 8px rgba(0,0,0,.6)}
    .call-status{font-size:15px;color:var(--sub,#8696a0)}
    .call-timer{font-variant-numeric:tabular-nums}
    .call-error{color:#f15c6d;text-align:center;max-width:280px;padding:0 20px}
    .call-remote-video{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
    .call-local-preview{position:absolute;top:16px;right:16px;width:110px;height:150px;
      border-radius:12px;object-fit:cover;box-shadow:0 4px 12px rgba(0,0,0,.4)}
    .call-local-preview-small{width:90px;height:120px;bottom:120px;top:auto}
    .call-actions{display:flex;gap:24px;position:absolute;bottom:60px}
    .call-actions-incoming{gap:60px}
    .call-actions-connected{gap:20px}
    .call-btn{width:60px;height:60px;border-radius:50%;border:none;font-size:24px;
      display:flex;align-items:center;justify-content:center;cursor:pointer}
    .call-btn-accept{background:#25d366;color:#04231a}
    .call-btn-reject,.call-btn-end{background:#f15c6d;color:#fff}
    .call-btn-secondary{background:var(--panel2,#182229);color:var(--tx,#e9edef);width:52px;height:52px;font-size:20px}
    .call-btn-active{background:#f15c6d;color:#fff}
    .call-toast{position:fixed;top:24px;left:50%;transform:translateX(-50%);
      background:var(--panel2,#182229);color:var(--tx,#e9edef);padding:10px 20px;
      border-radius:20px;z-index:600;font-size:14px}
  `;
  document.head.appendChild(style);
}

window.__initCallUI = initCallUI;
