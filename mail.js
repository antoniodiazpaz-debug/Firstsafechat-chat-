/* ═══════════════════════════════════════════════════════════════════════
   MAIL — SMTP-Versand über node:tls, ohne npm-Abhängigkeiten
   ─────────────────────────────────────────────────────────────────────
   Kein "nodemailer"-Paket — passend zum Zero-Dependency-Prinzip des
   restlichen Projekts (siehe push.js für dasselbe Muster bei Web Push).
   Implementiert genau das Teilstück von SMTP, das für einen einzelnen
   Versand über einen authentifizierten Account (z. B. Gmail) nötig ist:
   STARTTLS auf Port 587 mit AUTH LOGIN.

   Ohne konfiguriertes SMTP_HOST/SMTP_USER/SMTP_PASS in der Umgebung
   verschickt dieses Modul nichts, wirft aber auch keinen Fehler, der
   die Registrierung blockieren würde — siehe isConfigured() und den
   Kommentar zu email_verifications in server.js: ein Konto muss auch
   ohne konfigurierten Mailversand nutzbar bleiben.
   ═══════════════════════════════════════════════════════════════════════ */
const net = require('node:net');
const tls = require('node:tls');

function isConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

/* ─────────────────────────────────────────────────────────────────────
   Rohes SMTP-Gespräch über eine Socket-Verbindung.
   Jeder Schritt wartet auf die passende Antwortzeile, bevor er den
   nächsten Befehl schickt — SMTP ist zeilenbasiert und synchron.
───────────────────────────────────────────────────────────────────── */
function readLine(sock) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = chunk => {
      buf += chunk.toString('utf8');
      /* Eine SMTP-Antwort kann mehrzeilig sein ("250-..." gefolgt von
         "250 ..."); erst bei einer Zeile mit Leerzeichen nach dem Code
         ist die Antwort komplett. */
      const lines = buf.split('\r\n').filter(Boolean);
      const last = lines[lines.length - 1];
      if (last && /^\d{3} /.test(last)) {
        cleanup();
        resolve(buf);
      }
    };
    const onError = err => { cleanup(); reject(err); };
    const onClose = () => { cleanup(); reject(new Error('Verbindung geschlossen, bevor eine Antwort kam')); };
    function cleanup() {
      sock.removeListener('data', onData);
      sock.removeListener('error', onError);
      sock.removeListener('close', onClose);
    }
    sock.on('data', onData);
    sock.on('error', onError);
    sock.on('close', onClose);
  });
}

function expectCode(response, expected) {
  const code = response.slice(0, 3);
  if (code !== String(expected)) {
    throw new Error(`SMTP erwartete ${expected}, bekam: ${response.trim()}`);
  }
}

function send(sock, line) {
  sock.write(line + '\r\n');
}

/* Adressen/Betreff mit Nicht-ASCII müssen für den Header kodiert werden
   (RFC 2047) — sonst zerlegt ein strikter Mailserver den Header falsch. */
function encodeHeader(str) {
  if (/^[\x20-\x7E]*$/.test(str)) return str;   // reines ASCII, keine Kodierung nötig
  return '=?UTF-8?B?' + Buffer.from(str, 'utf8').toString('base64') + '?=';
}

async function sendMail({ to, subject, text, html }) {
  if (!isConfigured()) {
    console.warn('MAIL: kein SMTP konfiguriert — Versand übersprungen (Konto bleibt trotzdem nutzbar)');
    return { sent: false, reason: 'not-configured' };
  }

  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM || user;

  /* Port 587 = STARTTLS (Klartext-Verbindung, dann auf TLS hochstufen).
     Port 465 = direktes TLS von Anfang an. Beide werden unterstützt,
     weil manche Anbieter nur eines der beiden Verfahren erlauben. */
  const isDirectTls = port === 465;
  let sock = isDirectTls
    ? tls.connect({ host, port, servername: host })
    : net.connect({ host, port });

  /* WICHTIG: Ein TLS-Socket feuert ZUERST 'connect' (TCP-Verbindung
     steht) und ERST DANACH 'secureConnect' (TLS-Handshake fertig) —
     das sind zwei verschiedene Zeitpunkte, kein Alias füreinander.
     Auf 'connect' allein zu warten hieße, SMTP-Daten zu schreiben,
     während die TLS-Aushandlung noch läuft — das hängt lautlos, weil
     die Gegenseite die Bytes nicht als Klartext-SMTP interpretieren
     kann. Bei direktem TLS (Port 465) daher NUR secureConnect
     abwarten; bei Klartext (Port 587, vor STARTTLS) ist 'connect'
     korrekt, weil dort noch keine TLS-Schicht existiert. */
  await new Promise((resolve, reject) => {
    if (isDirectTls) sock.once('secureConnect', resolve);
    else sock.once('connect', resolve);
    sock.once('error', reject);
  });

  try {
    expectCode(await readLine(sock), 220);

    send(sock, 'EHLO securechat');
    expectCode(await readLine(sock), 250);

    if (port !== 465) {
      send(sock, 'STARTTLS');
      expectCode(await readLine(sock), 220);
      /* Ab hier läuft dieselbe TCP-Verbindung TLS-verschlüsselt weiter —
         node:tls kann eine bestehende Socket-Verbindung "upgraden". */
      sock = tls.connect({ socket: sock, servername: host });
      await new Promise((resolve, reject) => {
        sock.once('secureConnect', resolve);
        sock.once('error', reject);
      });
      send(sock, 'EHLO securechat');
      expectCode(await readLine(sock), 250);
    }

    send(sock, 'AUTH LOGIN');
    expectCode(await readLine(sock), 334);
    send(sock, Buffer.from(user).toString('base64'));
    expectCode(await readLine(sock), 334);
    send(sock, Buffer.from(pass).toString('base64'));
    expectCode(await readLine(sock), 235);   // Anmeldung akzeptiert

    send(sock, `MAIL FROM:<${from}>`);
    expectCode(await readLine(sock), 250);
    send(sock, `RCPT TO:<${to}>`);
    expectCode(await readLine(sock), 250);

    send(sock, 'DATA');
    expectCode(await readLine(sock), 354);

    const boundary = 'securechat-' + Date.now();
    const headers = [
      `From: SecureChat <${from}>`,
      `To: <${to}>`,
      `Subject: ${encodeHeader(subject)}`,
      `MIME-Version: 1.0`,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      ''
    ].join('\r\n');

    const body = [
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      '',
      text,
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      '',
      html,
      `--${boundary}--`
    ].join('\r\n');

    /* Zeilen, die zufällig nur aus einem Punkt bestehen, müssen laut
       RFC verdoppelt werden ("dot-stuffing") — sonst würde die
       Empfänger-Software sie fälschlich als DATA-Ende lesen.

       WICHTIG: Das Stuffing darf nur auf die tatsächlichen Inhalts-
       zeilen wirken, NIEMALS auf den abschließenden ".\r\n"-Terminator
       selbst — der markiert laut SMTP das Ende der Nachricht. Würde
       man ihn mitstuffen, entstünde "..\r\n" statt ".\r\n", der Server
       erkennt das nicht mehr als Ende und die Verbindung hängt, weil
       nie ein gültiger Abschluss ankommt (das war ein echter Bug hier:
       der Terminator stand ursprünglich VOR dem replace(), wurde also
       versehentlich mitverdoppelt). Reihenfolge daher: erst stuffen,
       dann den bloßen Terminator anhängen. */
    const stuffedContent = (headers + body).replace(/\r\n\./g, '\r\n..');
    send(sock, stuffedContent + '\r\n.');
    expectCode(await readLine(sock), 250);

    send(sock, 'QUIT');
    sock.end();
    return { sent: true };
  } catch (err) {
    try { sock.destroy(); } catch {}
    throw err;
  }
}

/* ─────────────────────────────────────────────────────────────────────
   Fertige Vorlagen für die drei Anwendungsfälle
───────────────────────────────────────────────────────────────────── */
async function sendVerificationCode(to, code) {
  return sendMail({
    to,
    subject: 'Dein Bestätigungscode',
    text: `Dein Bestätigungscode lautet: ${code}\n\nEr ist 15 Minuten gültig.`,
    html: `<p>Dein Bestätigungscode lautet:</p>
           <p style="font-size:28px;font-weight:bold;letter-spacing:4px">${code}</p>
           <p style="color:#666">Er ist 15 Minuten gültig. Falls du das nicht warst, ignoriere diese Mail.</p>`
  });
}

async function sendPasswordReset(to, resetLink) {
  return sendMail({
    to,
    subject: 'Passwort zurücksetzen',
    text: `Zum Zurücksetzen deines Passworts, öffne diesen Link: ${resetLink}\n\nEr ist 30 Minuten gültig.`,
    html: `<p>Zum Zurücksetzen deines Passworts:</p>
           <p><a href="${resetLink}">${resetLink}</a></p>
           <p style="color:#666">Der Link ist 30 Minuten gültig. Falls du das nicht warst, ignoriere diese Mail.</p>`
  });
}

async function sendNewMessageNotice(to, senderName) {
  return sendMail({
    to,
    subject: `Neue Nachricht von ${senderName}`,
    text: `Du hast eine neue Nachricht von ${senderName} erhalten.`,
    html: `<p>Du hast eine neue Nachricht von <strong>${senderName}</strong> erhalten.</p>`
  });
}

module.exports = {
  isConfigured,
  sendMail,
  sendVerificationCode,
  sendPasswordReset,
  sendNewMessageNotice
};
