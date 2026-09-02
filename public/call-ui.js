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
  } else if (state.state === 'calling') {
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
        <button class="call-btn call-btn-reject" id="callRejectBtn" aria-label="Ablehnen"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" style="transform:rotate(135deg)"><path d="M6.6 10.8c1.4 2.8 3.7 5 6.5 6.5l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C9.6 21 3 14.4 3 6c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.4 0 .8-.2 1L6.6 10.8z"/></svg></button>
        <button class="call-btn call-btn-accept" id="callAcceptBtn" aria-label="Annehmen"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M6.6 10.8c1.4 2.8 3.7 5 6.5 6.5l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C9.6 21 3 14.4 3 6c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.4 0 .8-.2 1L6.6 10.8z"/></svg></button>
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
      ${call.kind === 'video' ? '<video id="callLocalVideo" class="call-local-preview call-local-mirrored" autoplay muted playsinline></video>' : ''}
      <div class="call-actions">
        <button class="call-btn call-btn-end" id="callEndBtn" aria-label="Auflegen"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" style="transform:rotate(135deg)"><path d="M6.6 10.8c1.4 2.8 3.7 5 6.5 6.5l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C9.6 21 3 14.4 3 6c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.4 0 .8-.2 1L6.6 10.8z"/></svg></button>
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
      ${call.kind === 'video' ? '<video id="callLocalVideo" class="call-local-preview call-local-mirrored" autoplay muted playsinline></video>' : ''}
      <div class="call-actions">
        <button class="call-btn call-btn-end" id="callEndBtn" aria-label="Auflegen"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" style="transform:rotate(135deg)"><path d="M6.6 10.8c1.4 2.8 3.7 5 6.5 6.5l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C9.6 21 3 14.4 3 6c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.4 0 .8-.2 1L6.6 10.8z"/></svg></button>
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
      <audio id="callRemoteAudio" autoplay playsinline></audio>
      <div class="call-peername ${isVideo ? 'call-peername-overlay' : ''}">${escapeHtml(call.peerName)}</div>
      <div class="call-status call-timer" id="callTimer">00:00</div>
      ${isVideo ? '<video id="callLocalVideo" class="call-local-preview call-local-preview-small call-local-mirrored" autoplay muted playsinline></video>' : ''}
      ${isVideo ? '<button class="call-swap-btn" id="callSwapBtn" aria-label="Video tauschen"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 4v16M7 4l-3 3M7 4l3 3M17 20V4M17 20l-3-3M17 20l3-3"/></svg></button>' : ''}
      <div class="call-volume">
        <span class="call-volume-ic">🔉</span>
        <input type="range" id="callVolumeSlider" min="0" max="100" value="100" aria-label="Lautstärke">
        <span class="call-volume-ic">🔊</span>
      </div>
      <div class="call-actions call-actions-connected">
        <button class="call-btn call-btn-secondary" id="callMuteBtn" aria-label="Stummschalten">🎤</button>
        ${isVideo ? '<button class="call-btn call-btn-secondary" id="callCamBtn" aria-label="Kamera">📷</button>' : ''}
        ${isVideo ? '<button class="call-btn call-btn-secondary" id="callFlipBtn" aria-label="Kamera wechseln">🔄</button>' : ''}
        <button class="call-btn call-btn-end" id="callEndBtn" aria-label="Auflegen"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" style="transform:rotate(135deg)"><path d="M6.6 10.8c1.4 2.8 3.7 5 6.5 6.5l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1C9.6 21 3 14.4 3 6c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.2.2 2.4.6 3.6.1.4 0 .8-.2 1L6.6 10.8z"/></svg></button>
      </div>
    </div>
  `));

  remoteVideoEl = document.getElementById('callRemoteVideo');
  localVideoEl = document.getElementById('callLocalVideo');
  const remoteAudioEl = document.getElementById('callRemoteAudio');
  if (remoteVideoEl && remoteStream) remoteVideoEl.srcObject = remoteStream;
  /* Bei Audio-Anrufen kommt der Ton NUR über dieses <audio>-Element —
     ohne dieses Element würde der Gesprächspartner zwar verbunden,
     aber komplett lautlos bleiben. Bei Videoanrufen dient es als
     redundante zweite Wiedergabequelle, schadet aber nicht (derselbe
     MediaStream kann parallel an mehreren Elementen hängen). */
  if (remoteAudioEl && remoteStream) remoteAudioEl.srcObject = remoteStream;
  if (localVideoEl) makeDraggable(localVideoEl);

  /* In-App-Lautstärkeregler — steuert die Wiedergabelautstärke des
     Remote-Streams direkt. Physische Lautstärketasten steuern parallel
     die System-Medienlautstärke (Browser-Sicherheitsmodell erlaubt
     keinen direkten JS-Zugriff auf Hardware-Tasten); dieser Slider ist
     die einzige Möglichkeit, die Gesprächslautstärke ohne Tasten aus
     der App heraus zu regeln. */
  const volSlider = document.getElementById('callVolumeSlider');
  if (volSlider) {
    const savedVol = parseInt(localStorage.getItem('sc:callVolume') || '100', 10);
    volSlider.value = savedVol;
    const applyVolume = (v) => {
      const vol = Math.max(0, Math.min(100, v)) / 100;
      if (remoteAudioEl) remoteAudioEl.volume = vol;
      if (remoteVideoEl) remoteVideoEl.volume = vol;
    };
    applyVolume(savedVol);
    volSlider.oninput = (e) => {
      const v = parseInt(e.target.value, 10);
      applyVolume(v);
      localStorage.setItem('sc:callVolume', String(v));
    };
  }

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
  const flipBtn = document.getElementById('callFlipBtn');
  if (flipBtn) flipBtn.onclick = async () => {
    flipBtn.disabled = true;
    try { await Call.switchCamera(); } catch (e) { /* Gerät hat evtl. nur eine Kamera */ }
    flipBtn.disabled = false;
  };

  /* Tausch: großes und kleines Bild wechseln die Rolle. Statt die
     Video-Elemente selbst zu verschieben (würde srcObject/Playback
     unterbrechen), werden nur ihre CSS-Klassen vertauscht — der
     Browser behält beide MediaStreams am Laufen, nur die Darstellung
     ändert sich. isSwapped hält den Zustand für die aktuelle
     render()-Instanz, geht beim nächsten vollen Rerender verloren
     (z. B. Kamerawechsel) — das ist bewusst so, damit ein Kamera-
     Wechsel nicht in einem unerwartet vertauschten Zustand endet. */
  let isSwapped = false;
  const swapBtn = document.getElementById('callSwapBtn');
  if (swapBtn) swapBtn.onclick = () => {
    isSwapped = !isSwapped;
    /* Position/Inline-Styles vom Dragging zurücksetzen — sonst würde
       ein zuvor verschobenes PiP-Fenster seine alte Bildschirmposition
       auf die neue Rolle (großes Vollbild) übertragen. */
    remoteVideoEl.style.cssText = '';
    localVideoEl.style.cssText = '';
    if (isSwapped) {
      remoteVideoEl.className = 'call-local-preview call-local-preview-small';
      localVideoEl.className = 'call-remote-video call-local-mirrored';
    } else {
      remoteVideoEl.className = 'call-remote-video';
      localVideoEl.className = 'call-local-preview call-local-preview-small call-local-mirrored';
    }
  };

  startCallTimer();
}

/* Macht ein Element per Touch/Maus frei verschiebbar innerhalb des
   Viewports — für das kleine Selbstbild-Fenster (PiP) im Videoanruf.
   Nutzt Pointer Events statt separater touch/mouse-Handler, damit
   Maus UND Touch mit demselben Code funktionieren. */
function makeDraggable(elm) {
  let startX = 0, startY = 0, origX = 0, origY = 0, dragging = false;

  elm.style.touchAction = 'none';
  elm.addEventListener('pointerdown', (e) => {
    dragging = true;
    elm.setPointerCapture(e.pointerId);
    const rect = elm.getBoundingClientRect();
    origX = rect.left;
    origY = rect.top;
    startX = e.clientX;
    startY = e.clientY;
    /* Von rechts/unten-Positionierung (CSS) auf feste left/top umschalten,
       sonst würde die erste Bewegung springen. */
    elm.style.right = 'auto';
    elm.style.bottom = 'auto';
    elm.style.left = origX + 'px';
    elm.style.top = origY + 'px';
  });

  elm.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    let newX = origX + dx;
    let newY = origY + dy;
    /* Innerhalb des Viewports halten */
    const maxX = window.innerWidth - elm.offsetWidth;
    const maxY = window.innerHeight - elm.offsetHeight;
    newX = Math.max(0, Math.min(maxX, newX));
    newY = Math.max(0, Math.min(maxY, newY));
    elm.style.left = newX + 'px';
    elm.style.top = newY + 'px';
  });

  const stop = (e) => { dragging = false; try { elm.releasePointerCapture(e.pointerId); } catch {} };
  elm.addEventListener('pointerup', stop);
  elm.addEventListener('pointercancel', stop);
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
  Call.subscribeCameraSwitch(({ localStream, facingMode }) => {
    if (localVideoEl) {
      localVideoEl.srcObject = localStream;
      localVideoEl.classList.toggle('call-local-mirrored', facingMode === 'user');
    }
  });
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
    .call-local-preview{position:fixed;top:16px;right:16px;width:110px;height:150px;
      border-radius:12px;object-fit:cover;box-shadow:0 4px 12px rgba(0,0,0,.4);
      cursor:grab;z-index:610}
    .call-local-preview.call-local-mirrored{transform:scaleX(-1)}
    .call-local-preview:active{cursor:grabbing}
    .call-local-preview-small{width:90px;height:120px;bottom:120px;top:auto}
    .call-actions{display:flex;gap:24px;position:absolute;bottom:60px}
    .call-actions-incoming{gap:60px}
    .call-actions-connected{gap:20px}
    .call-volume{display:flex;align-items:center;gap:10px;width:min(280px,80vw);
      position:absolute;bottom:150px;padding:8px 16px;background:rgba(0,0,0,.35);
      border-radius:24px;backdrop-filter:blur(4px)}
    .call-volume-ic{font-size:16px;flex-shrink:0}
    .call-volume input[type=range]{flex:1;accent-color:#25d366;height:4px}
    .call-btn{width:60px;height:60px;border-radius:50%;border:none;font-size:24px;
      display:flex;align-items:center;justify-content:center;cursor:pointer}
    .call-btn-accept{background:radial-gradient(circle at 35% 30%,var(--call-accept-2,#4ade80),var(--call-accept-1,#16a34a) 70%);
      color:#04231a;border:2px solid rgba(255,255,255,.4);
      box-shadow:0 3px 6px rgba(0,0,0,.4),inset 0 1px 1px rgba(255,255,255,.3)}
    .call-btn-reject,.call-btn-end{background:radial-gradient(circle at 35% 30%,var(--call-end-2,#f87171),var(--call-end-1,#dc2626) 70%);
      color:#fff;border:2px solid rgba(255,255,255,.4);
      box-shadow:0 3px 6px rgba(0,0,0,.4),inset 0 1px 1px rgba(255,255,255,.3)}
    .call-btn-secondary{background:var(--panel2,#182229);color:var(--tx,#e9edef);width:52px;height:52px;font-size:20px}
    .call-btn-active{background:#f15c6d;color:#fff}
    .call-toast{position:fixed;top:24px;left:50%;transform:translateX(-50%);
      background:var(--panel2,#182229);color:var(--tx,#e9edef);padding:10px 20px;
      border-radius:20px;z-index:600;font-size:14px}
  `;
  document.head.appendChild(style);
}

window.__initCallUI = initCallUI;
