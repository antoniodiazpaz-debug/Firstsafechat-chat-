/* Testet die reinen Logikfunktionen aus public/device-info.js —
   Spracherkennung, Vorwahl-Ableitung, Feld-Vorbereitung, WebOTP-Fallback.
   Läuft mit dem root-loader.mjs, der "/device-info.js" (Browser-Notation)
   auf public/device-info.js abbildet. */
import { installBrowserMocks } from './test-helpers/browser-mocks.mjs';
installBrowserMocks();

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

/* Node 22 hat einen eingebauten, schreibgeschützten navigator-Getter.
   Object.defineProperty mit configurable:true macht ihn überschreibbar,
   damit jeder Testfall eine andere Sprache simulieren kann. Das Modul
   selbst ist zustandslos (liest navigator bei jedem Aufruf neu), daher
   genügt ein einmaliger Import ohne Cache-Busting. */
Object.defineProperty(globalThis, 'navigator', {
  value: { language: 'de-DE', languages: ['de-DE'] },
  configurable: true, writable: true
});
const M = await import('/device-info.js');

function withLang(lang, fn) {
  Object.defineProperty(globalThis, 'navigator', {
    value: { language: lang, languages: [lang] },
    configurable: true, writable: true
  });
  return fn(M);
}

console.log('detectLanguage():');
withLang('de-DE', M => {
  const r = M.detectLanguage();
  ok(r.full === 'de-DE', 'volle Locale erhalten');
  ok(r.base === 'de', 'Basissprache extrahiert');
  ok(r.supported === 'de', 'Deutsch ist unterstützt');
});
withLang('fr-CA', M => {
  const r = M.detectLanguage();
  ok(r.base === 'fr', 'Französisch (Kanada) erkannt');
  ok(r.supported === 'fr', 'Französisch ist unterstützt');
});
withLang('ja-JP', M => {
  const r = M.detectLanguage();
  ok(r.base === 'ja', 'Japanisch als Basissprache erkannt');
  ok(r.supported === 'en', 'nicht unterstützte Sprache fällt auf Englisch zurück, nicht auf undefined');
});

console.log('\nguessDialCode():');
withLang('de-DE', M => ok(M.guessDialCode() === '+49', 'Deutschland → +49'));
withLang('en-US', M => ok(M.guessDialCode() === '+1', 'USA → +1'));
withLang('en-GB', M => ok(M.guessDialCode() === '+44', 'UK → +44'));
withLang('pt-BR', M => ok(M.guessDialCode() === '+55', 'Brasilien → +55'));
withLang('en', M => ok(M.guessDialCode() === '+1', 'nur Basissprache "en" findet trotzdem eine Vorwahl über Fallback-Suche'));
withLang('xx-ZZ', M => ok(M.guessDialCode() === '', 'unbekannte Locale liefert leeren String statt zu raten'));

console.log('\npreparePhoneInput():');
const fakeInput = { attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
withLang('de-DE', M => {
  M.preparePhoneInput(fakeInput);
  ok(fakeInput.attrs.type === 'tel', 'Feldtyp auf tel gesetzt');
  ok(fakeInput.attrs.autocomplete === 'tel', 'autocomplete=tel gesetzt — das ist der Teil, den Browser-Autofill nutzt');
  ok(fakeInput.attrs.inputmode === 'tel', 'inputmode=tel für die richtige mobile Tastatur');
});

console.log('\nwatchForSmsCode() ohne WebOTP-Unterstützung:');
withLang('de-DE', M => {
  const r = M.watchForSmsCode({});
  ok(r.supported === false, 'meldet korrekt "nicht unterstützt", statt zu crashen, wenn OTPCredential fehlt');
  ok(typeof r.cancel === 'function', 'liefert trotzdem eine no-op cancel-Funktion — Aufrufer muss nicht verzweigen');
});

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
