/* ═══════════════════════════════════════════════════════════════════════
   DEVICE-INFO — Spracheinstellung und Telefonnummer-Erkennung
   ─────────────────────────────────────────────────────────────────────
   Sprache: navigator.language ist zuverlässig und plattformübergreifend
   verfügbar, keine Berechtigung nötig.

   Telefonnummer: Kein Browser erlaubt automatisches Auslesen der eigenen
   Rufnummer — das wäre ein Datenschutzloch (jede Webseite könnte sonst
   die Nummer jedes Besuchers abgreifen). Was real existiert:

   1. WebOTP API (Chrome/Android): Bei einer eingehenden SMS mit der
      richtigen Struktur füllt der Browser ein <input autocomplete="one-time-code">
      automatisch aus. Das ist für Verifizierungscodes gedacht, nicht für
      die Nummer selbst — die Nummer tippt der Nutzer weiterhin ein,
      aber der Bestätigungscode danach nicht mehr.
   2. tel:-Autofill des Browsers/Betriebssystems (alle Plattformen):
      Browser können gespeicherte Kontaktdaten (auch die eigene Nummer,
      wenn im Adressbuch/Autofill-Profil hinterlegt) in <input type="tel">
      vorschlagen — das ist Autofill, keine JS-API, funktioniert also
      "von selbst", wenn autocomplete korrekt gesetzt ist.

   Beides ist Autofill-Unterstützung, kein automatisches, unsichtbares
   Auslesen. Das ist Absicht, nicht eine Einschränkung dieses Moduls.
   ═══════════════════════════════════════════════════════════════════════ */

/* ── Sprache ── */
export function detectLanguage() {
  const raw = navigator.language || navigator.languages?.[0] || 'de-DE';
  const base = raw.split('-')[0].toLowerCase();
  return { full: raw, base, supported: SUPPORTED_LANGS.includes(base) ? base : 'en' };
}
export const SUPPORTED_LANGS = ['de', 'en', 'es', 'fr', 'tr', 'ar', 'pt', 'it'];

/* Ländervorwahl aus der Browser-/Systemsprache ableiten — reine
   Bequemlichkeit für das Telefonfeld, keine Ortung, keine IP-Abfrage. */
const LOCALE_DIAL_CODES = {
  'de-DE': '+49', 'de-AT': '+43', 'de-CH': '+41',
  'en-US': '+1', 'en-GB': '+44', 'en-CA': '+1', 'en-AU': '+61',
  'fr-FR': '+33', 'es-ES': '+34', 'it-IT': '+39',
  'pt-PT': '+351', 'pt-BR': '+55', 'tr-TR': '+90', 'nl-NL': '+31',
  'pl-PL': '+48', 'ar-SA': '+966'
};
export function guessDialCode() {
  const full = navigator.language || 'de-DE';
  if (LOCALE_DIAL_CODES[full]) return LOCALE_DIAL_CODES[full];
  const base = full.split('-')[0];
  const match = Object.entries(LOCALE_DIAL_CODES).find(([k]) => k.startsWith(base + '-'));
  return match ? match[1] : '';
}

/* ── WebOTP: Bestätigungscode automatisch übernehmen ──
   Erwartet ein <input> und eine SMS mit einer Zeile "@deinedomain.de #123456"
   am Ende (WebOTP-Format). Bricht sauber ab, wenn die API fehlt oder das
   Feld verschwindet (Nutzer hat z. B. abgebrochen), statt hängen zu bleiben. */
export function watchForSmsCode(inputEl, { timeoutMs = 60000 } = {}) {
  if (!('OTPCredential' in window) || !navigator.credentials?.get) {
    return { supported: false, cancel() {} };
  }
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);

  navigator.credentials.get({
    otp: { transport: ['sms'] }, signal: ac.signal
  }).then(cred => {
    if (cred?.code && inputEl) {
      inputEl.value = cred.code;
      inputEl.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }).catch(() => { /* abgebrochen oder verweigert — kein Fehlerzustand */ })
    .finally(() => clearTimeout(timer));

  return { supported: true, cancel: () => ac.abort() };
}

/* ── Telefonfeld korrekt für Autofill vorbereiten ──
   autocomplete="tel" ist der Teil, den Browser/OS tatsächlich auswerten,
   um eine hinterlegte eigene Nummer vorzuschlagen. Kein JS liest hier
   etwas aus — das Feld wird nur so beschriftet, dass die Autofill-
   Heuristik des Browsers greifen kann. */
export function preparePhoneInput(inputEl) {
  inputEl.setAttribute('type', 'tel');
  inputEl.setAttribute('autocomplete', 'tel');
  inputEl.setAttribute('inputmode', 'tel');
}
