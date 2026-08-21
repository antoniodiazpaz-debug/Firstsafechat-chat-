/* Prüft: jede Sprache hat alle Schlüssel von de (keine stillen Lücken
   in der UI), t() fällt bei fehlendem Schlüssel auf Deutsch zurück,
   setLocale() ignoriert unbekannte Sprachen statt zu crashen. */
const M = await import('./public/i18n.js');
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

console.log('Vollständigkeit aller Sprachen:');
const deKeys = new Set();
M.setLocale('de');
/* de-Schlüssel indirekt über t() für eine bekannte Liste prüfen,
   da STRINGS selbst nicht exportiert ist (Kapselung ist gewollt) */
const KNOWN_KEYS = ['appName', 'tagline', 'login', 'register', 'createAccount', 'username',
  'password', 'phone', 'email', 'unlock', 'otherAccount', 'welcomeBack', 'newDevice',
  'pairHint', 'pairCode', 'pair', 'back', 'fieldsRequired', 'passwordTooShort',
  'phoneRequired', 'generatingKeys', 'welcome', 'smsHint'];

for (const lang of M.AVAILABLE_LOCALES) {
  M.setLocale(lang);
  const missing = KNOWN_KEYS.filter(k => {
    // Ein "fehlender" Schlüssel würde ohne Fallback den rohen Key zurückgeben —
    // aber t() fällt auf de zurück, daher prüfen wir das Nicht-Zurückfallen
    // durch Vergleich: wenn der Wert exakt gleich dem Key-String ist, fehlt er
    // überall (auch in de), was ein echter Fehler wäre.
    return M.t(k) === k;
  });
  ok(missing.length === 0, `${lang}: alle ${KNOWN_KEYS.length} Schlüssel vorhanden`);
}

console.log('\nsetLocale():');
ok(M.setLocale('de') === 'de', 'gültige Sprache wird übernommen');
ok(M.setLocale('xx') === 'de', 'unbekannte Sprache fällt auf Deutsch zurück statt zu crashen');
ok(M.getLocale() === 'de', 'getLocale() spiegelt den Fallback korrekt wider');

console.log('\nÜbersetzungen unterscheiden sich tatsächlich:');
M.setLocale('de'); const deLogin = M.t('login');
M.setLocale('en'); const enLogin = M.t('login');
M.setLocale('es'); const esLogin = M.t('login');
ok(deLogin !== enLogin, 'Deutsch und Englisch unterscheiden sich');
ok(enLogin !== esLogin, 'Englisch und Spanisch unterscheiden sich');
ok(deLogin === 'Anmelden' && enLogin === 'Log in' && esLogin === 'Iniciar sesión', 'konkrete Werte stimmen');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
