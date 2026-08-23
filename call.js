/* ═══════════════════════════════════════════════════════════════════════
   CALL — WebRTC-Anrufe (Sprache & Video), 1:1
   ─────────────────────────────────────────────────────────────────────
   Nutzt die bestehende WebSocket-Verbindung (api.wsSend/api.on) für die
   Signalisierung — der Server reicht nur SDP-Angebot/-Antwort und ICE-
   Kandidaten durch, sieht nie den eigentlichen Medienstrom. Der Audio-/
   Videostrom läuft danach direkt (peer-to-peer) zwischen den Browsern.

   Öffentliche API:
     Call.start(peerId, peerName, kind)   — Anruf beginnen ('audio'|'video')
     Call.wire(api)                        — einmalig beim App-Start aufrufen,
                                              hängt die Signalisierungs-
                                              Handler an die WebSocket-
                                              Verbindung
   ═══════════════════════════════════════════════════════════════════════ */

const Call = (() => {
  /* Öffentliche STUN-Server von Google — kostenlos, reicht für die
     meisten Verbindungen (beide Teilnehmer hinter normalem NAT/Router).
     Für Nutzer hinter restriktiven Firewalls (z. B. manche Firmennetze)
     bräuchte es zusätzlich einen TURN-Server, der tatsächlich Traffic
     durchleitet — das ist ein möglicher Ausbau für später, kostet aber
     laufend Bandbreite und ist deshalb bewusst nicht im Basis-Setup. */
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ];

  let api = null;
  let pc = null;              // aktuelle RTCPeerConnection
  let localStream = null;
  let currentCall = null;     // { callId, peerId, peerName, kind, role: 'caller'|'callee' }
  let ringTimeout = null;
  let onStateChange = () => {};   // von der UI gesetzt, um Oberfläche zu aktualisieren

  function log(...args) { console.log('[Call]', ...args); }

  /* ── Öffentlich: UI registriert sich hier für Zustandsänderungen ── */
  function subscribe(fn) { onStateChange = fn; }

  function notify(state, extra = {}) {
    onStateChange({ state, call: currentCall, ...extra });
  }

  /* ── Anruf beginnen (Anrufer-Seite) ── */
  async function start(peerId, peerName, kind = 'audio') {
    if (currentCall) { log('Bereits in einem Anruf, breche ab'); return; }
    const callId = 'call-' + crypto.randomUUID();
    currentCall = { callId, peerId, peerName, kind, role: 'caller' };
    notify('calling');

    try {
      localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: kind === 'video' ? { facingMode: 'user' } : false
      });
    } catch (err) {
      log('Kamera/Mikrofon-Zugriff verweigert oder nicht verfügbar:', err.message);
      notify('error', { reason: 'no-media', message: err.message });
      currentCall = null;
      return;
    }

    notify('calling', { localStream });

    pc = buildPeerConnection();
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    api.wsSend({ type: 'call-offer', to: peerId, callId, kind, sdp: offer.sdp });

    /* Klingelt maximal 45 Sekunden — danach automatisch abbrechen, damit
       der Anrufer nicht endlos wartet, falls der Empfänger die App zwar
       offen hat, aber nicht reagiert. */
    ringTimeout = setTimeout(() => {
      if (currentCall?.callId === callId) {
        log('Keine Antwort innerhalb von 45s, breche Anruf ab');
        endCall('no-answer');
      }
    }, 45000);
  }

  /* ── Eingehender Anruf (Callee-Seite) — wird von der UI aufgerufen,
     nachdem der Nutzer auf "Annehmen" getippt hat ── */
  async function accept() {
    if (!currentCall || currentCall.role !== 'ringing') return;
    const { callId, peerId, kind, offerSdp } = currentCall;

    try {
      localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: kind === 'video' ? { facingMode: 'user' } : false
      });
    } catch (err) {
      log('Kamera/Mikrofon-Zugriff verweigert:', err.message);
      api.wsSend({ type: 'call-reject', to: peerId, callId, reason: 'no-media' });
      currentCall = null;
      notify('idle');
      return;
    }

    currentCall.role = 'callee';
    notify('connecting', { localStream });

    pc = buildPeerConnection();
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));

    await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    api.wsSend({ type: 'call-answer', to: peerId, callId, sdp: answer.sdp });

    /* Zwischengespeicherte ICE-Kandidaten, die ankamen, bevor die
       Remote-Beschreibung gesetzt war, jetzt nachträglich anwenden. */
    flushPendingCandidates();
  }

  function reject() {
    if (!currentCall) return;
    api.wsSend({ type: 'call-reject', to: currentCall.peerId, callId: currentCall.callId, reason: 'declined' });
    cleanup();
    notify('idle');
  }

  function endCall(reason = 'ended') {
    if (currentCall) {
      api.wsSend({ type: 'call-end', to: currentCall.peerId, callId: currentCall.callId });
    }
    cleanup();
    notify('idle', { reason });
  }

  /* ── RTCPeerConnection mit den üblichen Event-Handlern aufbauen ── */
  let pendingCandidates = [];
  function buildPeerConnection() {
    const conn = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    conn.onicecandidate = e => {
      if (e.candidate && currentCall) {
        api.wsSend({ type: 'call-ice', to: currentCall.peerId, callId: currentCall.callId, candidate: e.candidate });
      }
    };

    conn.ontrack = e => {
      notify('connected', { remoteStream: e.streams[0] });
      clearTimeout(ringTimeout);
    };

    conn.onconnectionstatechange = () => {
      log('Verbindungsstatus:', conn.connectionState);
      if (conn.connectionState === 'failed' || conn.connectionState === 'disconnected') {
        notify('error', { reason: 'connection-lost' });
        cleanup();
      }
    };

    return conn;
  }

  function flushPendingCandidates() {
    for (const c of pendingCandidates) {
      pc.addIceCandidate(c).catch(err => log('ICE-Kandidat konnte nicht angewendet werden:', err.message));
    }
    pendingCandidates = [];
  }

  function cleanup() {
    clearTimeout(ringTimeout);
    if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
    if (pc) { pc.close(); pc = null; }
    pendingCandidates = [];
    currentCall = null;
  }

  /* ── Stummschalten / Kamera an-aus, während der Anruf läuft ── */
  function toggleMute() {
    if (!localStream) return false;
    const track = localStream.getAudioTracks()[0];
    if (!track) return false;
    track.enabled = !track.enabled;
    return !track.enabled;   // true = jetzt stummgeschaltet
  }
  function toggleCamera() {
    if (!localStream) return false;
    const track = localStream.getVideoTracks()[0];
    if (!track) return false;
    track.enabled = !track.enabled;
    return !track.enabled;   // true = Kamera jetzt aus
  }

  /* ── Signalisierungs-Nachrichten vom Server verdrahten ──
     Folgt demselben Muster wie wireSocketEvents() in app.js. ── */
  function wire(apiClient) {
    api = apiClient;

    api.on('call-offer', msg => {
      if (currentCall) {
        /* Schon in einem anderen Anruf — höflich ablehnen, nicht
           einfach ignorieren, damit der Anrufer sofort "besetzt" sieht
           statt in die 45-Sekunden-Klingelzeit zu laufen. */
        api.wsSend({ type: 'call-reject', to: msg.from, callId: msg.callId, reason: 'busy' });
        return;
      }
      currentCall = {
        callId: msg.callId, peerId: msg.from, peerName: msg.fromName || msg.from,
        kind: msg.kind, role: 'ringing', offerSdp: msg.sdp
      };
      notify('ringing');
    });

    api.on('call-answer', async msg => {
      if (!currentCall || currentCall.callId !== msg.callId || !pc) return;
      await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
      flushPendingCandidates();
      notify('connecting');
    });

    api.on('call-ice', msg => {
      if (!currentCall || currentCall.callId !== msg.callId) return;
      const candidate = new RTCIceCandidate(msg.candidate);
      if (pc && pc.remoteDescription) {
        pc.addIceCandidate(candidate).catch(err => log('ICE-Kandidat fehlgeschlagen:', err.message));
      } else {
        /* Remote-Beschreibung noch nicht gesetzt (Callee-Seite, bevor
           accept() gelaufen ist) — für später zwischenspeichern, statt
           den Kandidaten zu verwerfen. */
        pendingCandidates.push(candidate);
      }
    });

    api.on('call-reject', msg => {
      if (!currentCall || currentCall.callId !== msg.callId) return;
      const reason = msg.reason;
      cleanup();
      notify('idle', { reason: reason === 'busy' ? 'peer-busy' : 'declined' });
    });

    api.on('call-end', msg => {
      if (!currentCall || currentCall.callId !== msg.callId) return;
      cleanup();
      notify('idle', { reason: 'peer-ended' });
    });

    api.on('call-unavailable', msg => {
      if (!currentCall || currentCall.callId !== msg.callId) return;
      cleanup();
      notify('idle', { reason: 'unavailable' });
    });
  }

  return { start, accept, reject, endCall, toggleMute, toggleCamera, subscribe, wire };
})();

export { Call };
