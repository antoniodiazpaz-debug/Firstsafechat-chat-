/* ═══════════════════════════════════════════════════════════════════════
   SENDER KEYS — Gruppenverschlüsselung mit Forward Secrecy
   ─────────────────────────────────────────────────────────────────────
   Ersetzt den früheren "ein AES-Schlüssel für die ganze Gruppe"-Ansatz
   (siehe app.js confirmCreateGroup, alte Version) durch das Sender-
   Keys-Prinzip, wie es Signal/WhatsApp für Gruppen nutzen:

   - JEDES Mitglied hat einen EIGENEN Sender-Key (Chain-Key + eigenes
     ECDSA-Signaturpaar), nicht einen gemeinsamen Gruppenschlüssel
   - Der Sender-Key wird EINMALIG an jedes andere Mitglied verteilt,
     verschlüsselt über die bestehende 1:1-Ratchet-Session (dieselbe
     X3DH/Double-Ratchet-Infrastruktur aus crypto-core.js — kein
     zweites Kryptoprimitiv nötig für die Verteilung selbst)
   - Jede gesendete Nachricht dreht die eigene Chain-Key-Kette weiter
     (exakt dasselbe HMAC-Verfahren wie Ratchet.kdfCK in crypto-core.js)
     — das ist das Forward-Secrecy-Element: wer den Chain-Key zum
     Zeitpunkt X kompromittiert, kann NICHT rückwirkend Nachrichten vor
     X entschlüsseln (die vorherigen Chain-Keys wurden bereits verworfen)
   - Jede Nachricht ist mit dem privaten Signaturschlüssel des Senders
     signiert — ein Empfänger kann verifizieren, dass eine Nachricht
     wirklich vom behaupteten Mitglied stammt, nicht vom Server
     untergeschoben wurde

   Was das NICHT löst (bewusste Grenze, wie bei den meisten
   Sender-Keys-Implementierungen): kein Post-Compromise-Security
   innerhalb der laufenden Kette — wird ein Chain-Key kompromittiert,
   kann der Angreifer ALLE folgenden Nachrichten dieses Senders lesen,
   bis die Gruppe explizit neu initialisiert wird (siehe rotateOnLeave
   in app.js integration). Das ist dieselbe Grenze, die Signal für
   Gruppen akzeptiert — echte Selbstheilung pro Nachricht bräuchte
   einen vollen asymmetrischen Ratchet pro Sender-Paar, was den aktiven
   Sender-Zahl-Aufwand quadratisch statt linear macht.
   ═══════════════════════════════════════════════════════════════════════ */
import { P, b64, ub64, te, td } from '/crypto-core.js';

const SenderKeys = {
  /* Neuer Sender-Key für EIN Mitglied — wird beim Gruppenbeitritt
     einmal erzeugt, danach nur noch über advance() weitergedreht. */
  async create() {
    const chainKey = crypto.getRandomValues(new Uint8Array(32));
    const signKeyPair = await P.genSign();
    return {
      chainKey,
      iteration: 0,
      signPriv: signKeyPair.priv,
      signPub: signKeyPair.pub,
      signPubJwk: signKeyPair.pubJwk
    };
  },

  /* Öffentlicher Teil, der an andere Mitglieder verteilt wird —
     NIEMALS chainKey im Klartext über einen ungeschützten Kanal, das
     passiert ausschließlich verschlüsselt über die 1:1-Ratchet-Session
     (siehe app.js distributeSenderKey). Dieses Objekt selbst ist die
     Nutzlast, die durch den Ratchet verschlüsselt wird. */
  exportForDistribution(sk) {
    return {
      chainKeyB64: b64(sk.chainKey),
      iteration: sk.iteration,
      signPubJwk: sk.signPubJwk
    };
  },

  /* Empfänger-Seite: aus der verteilten Nutzlast einen verifizierbaren
     Sender-Key für EIN fremdes Mitglied rekonstruieren. */
  async importDistributed(payload) {
    const signPub = await P.impVerify(payload.signPubJwk);
    return {
      chainKey: ub64(payload.chainKeyB64),
      iteration: payload.iteration,
      signPub,
      signPubJwk: payload.signPubJwk
    };
  },

  /* Chain-KDF: exakt dasselbe HMAC-Verfahren wie Ratchet.kdfCK in
     crypto-core.js — Message Key aus 0x01, nächster Chain Key aus
     0x02. Wiederverwendung des etablierten, bereits geprüften Musters
     statt einer eigenen Konstruktion. */
  async advance(chainKey) {
    const mk = await P.hmac(chainKey, new Uint8Array([0x01]));
    const nextChainKey = await P.hmac(chainKey, new Uint8Array([0x02]));
    return { messageKey: new Uint8Array(mk), nextChainKey: new Uint8Array(nextChainKey) };
  },

  /* ── Senden ──
     Dreht die EIGENE Kette einen Schritt weiter, verschlüsselt mit dem
     resultierenden Message Key, signiert das Chiffrat mit dem eigenen
     Sender-Key-Signaturschlüssel. sk wird MUTIERT (chainKey/iteration
     rücken vor) — der Aufrufer muss den neuen Zustand persistieren. */
  async encrypt(sk, plaintext, groupId) {
    const { messageKey, nextChainKey } = await SenderKeys.advance(sk.chainKey);
    const iteration = sk.iteration;
    sk.chainKey = nextChainKey;
    sk.iteration++;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = `senderkey-v1|${groupId}|${iteration}`;
    const ct = await P.seal(messageKey, iv, te.encode(plaintext), aad);
    const sig = await P.sign(sk.signPriv, new Uint8Array(ct));

    return {
      iteration,
      ivB64: b64(iv),
      ctB64: b64(new Uint8Array(ct)),
      sigB64: b64(sig)
    };
  },

  /* ── Empfangen ──
     senderState wird MUTIERT (chainKey/iteration rücken auf den Stand
     der empfangenen Nachricht vor) — der Aufrufer muss den neuen
     Zustand persistieren. Lehnt Nachrichten ab, deren iteration hinter
     dem bereits erreichten Stand liegt (Replay-Schutz) oder deren
     Signatur nicht zum bekannten Sender-Schlüssel passt. */
  async decrypt(senderState, envelope, groupId) {
    if (envelope.iteration < senderState.iteration) {
      throw new Error('Nachricht bereits verarbeitet oder zu alt (Replay-Schutz)');
    }
    /* Kette bis zur benötigten Iteration vorwärtsdrehen — bei
       Nachrichten, die außer der Reihe eintreffen (normal bei
       nebenläufigem Versand mehrerer Mitglieder), werden
       Zwischenschritte übersprungen, aber ordnungsgemäß durchlaufen,
       damit der Chain-Key-Zustand konsistent bleibt. */
    let chainKey = senderState.chainKey;
    let messageKey = null;
    for (let i = senderState.iteration; i <= envelope.iteration; i++) {
      const step = await SenderKeys.advance(chainKey);
      messageKey = step.messageKey;
      chainKey = step.nextChainKey;
    }
    senderState.chainKey = chainKey;
    senderState.iteration = envelope.iteration + 1;

    const ct = ub64(envelope.ctB64);
    const sigValid = await P.verify(senderState.signPub, ub64(envelope.sigB64), ct);
    if (!sigValid) throw new Error('Signatur ungültig — Nachricht wurde manipuliert oder Absender gefälscht');

    const aad = `senderkey-v1|${groupId}|${envelope.iteration}`;
    const plainBuf = await P.open(messageKey, ub64(envelope.ivB64), ct, aad);
    return td.decode(plainBuf);
  }
};

export { SenderKeys };
