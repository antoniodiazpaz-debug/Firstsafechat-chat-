/* Prüft die Integration von i18n und device-info in app.js: Die
   Registrierungsmaske übersetzt sich nach Systemsprache, das
   Telefonfeld bekommt Autofill-Attribute und eine geschätzte Vorwahl. */
import { installBrowserMocks } from './test-helpers/browser-mocks.mjs';
installBrowserMocks();

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

/* Ein minimales, aber funktionsfähiges DOM: genug für innerHTML +
   querySelector + Attribute + classList, ohne jsdom als Abhängigkeit. */
function makeFakeDom() {
  const elements = new Map();
  function parseAndRegister(html) {
    // Sehr einfache id-Extraktion — reicht für unsere generierten Templates
    const idRe = /id="([^"]+)"/g;
    let m;
    while ((m = idRe.exec(html))) {
      if (!elements.has(m[1])) {
        elements.set(m[1], {
          id: m[1], value: '', textContent: '', attrs: {},
          classList: { list: new Set(),
            add(c){this.list.add(c)}, remove(c){this.list.delete(c)},
            toggle(c,v){v?this.list.add(c):this.list.delete(c)},
            contains(c){return this.list.has(c)} },
          setAttribute(k,v){this.attrs[k]=v},
          getAttribute(k){return this.attrs[k]},
          addEventListener(){}
        });
      }
    }
  }
  return {
    _lastHtml: '',
    get innerHTML() { return this._lastHtml; },
    set innerHTML(html) { this._lastHtml = html; parseAndRegister(html); },
    querySelector(sel) {
      const id = sel.replace('#', '');
      return elements.get(id) || null;
    },
    classList: { add(){}, remove(){}, toggle(){} }
  };
}

const authEl = makeFakeDom();
const appEl = makeFakeDom();
globalThis.document = {
  getElementById: id => (id === 'auth' ? authEl : id === 'app' ? appEl : null),
  /* Mein ursprünglicher Mock kannte nur #auth/#app selbst — das ist der
     Bug, der die drei Assertions unten scheitern ließ: $('#aPhone') rief
     document.querySelector('#aPhone') auf, was hier null zurückgab,
     obwohl app.js völlig korrekt danach sucht. Realistischeres
     Verhalten: zuerst in beiden Teilbäumen nach der ID suchen. */
  querySelector: sel => {
    if (sel === '#auth') return authEl;
    if (sel === '#app') return appEl;
    const id = sel.replace('#', '');
    return authEl.querySelector(sel) || appEl.querySelector(sel) || null;
  },
  querySelectorAll: () => [],
  createElement: () => ({ classList: { add(){}, remove(){}, toggle(){} }, style:{} }),
  body: { appendChild(){} },
  documentElement: { lang: '' }
};

console.log('Deutsche Systemsprache:');
Object.defineProperty(globalThis, 'navigator', {
  value: { language: 'de-DE', languages: ['de-DE'], userAgent: 'test' },
  configurable: true, writable: true
});
globalThis.window = { SECURECHAT_CONFIG: {}, addEventListener(){}, crypto: globalThis.crypto };
globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
globalThis.indexedDB = { open: () => ({}) };
globalThis.location = { origin: 'http://test.local' };

const M = await import('/app.js');
M.renderAuthChoice();
ok(authEl.innerHTML.includes('Anmelden'), 'Login-Button auf Deutsch gerendert');
ok(authEl.innerHTML.includes('Registrieren'), 'Registrieren-Tab auf Deutsch');
ok(authEl.innerHTML.includes('+49'), 'deutsche Vorwahl als Platzhalter im Telefonfeld sichtbar');

const phoneField = authEl.querySelector('#aPhone');
ok(!!phoneField, 'Telefonfeld existiert im DOM-Mock');
ok(phoneField.value === '+49 ', 'Telefonfeld ist mit der geschätzten Vorwahl vorausgefüllt: "' + phoneField.value + '"');
ok(phoneField.attrs.autocomplete === 'tel', 'autocomplete=tel gesetzt — das ist der Teil, den Browser-Autofill nutzt');
ok(phoneField.attrs.type === 'tel', 'Feldtyp auf tel gesetzt für die richtige mobile Tastatur');

console.log('\nEnglische Systemsprache (anderes Browser-Fenster simuliert):');
/* setLocale wurde beim ersten app.js-Import bereits aufgerufen (Modul-
   Top-Level, läuft nur einmal) — hier direkt gegen die i18n-API prüfen,
   dass ein zweiter detectLanguage()-Aufruf mit anderer Sprache auch ein
   anderes Ergebnis liefert. Ein echter Sprachwechsel im laufenden
   Browser bräuchte einen expliziten Reload/Re-Render, das ist so
   vorgesehen (Sprache wird beim Boot einmal festgelegt). */
const i18n = await import('/i18n.js');
const devInfo = await import('/device-info.js');
Object.defineProperty(globalThis, 'navigator', {
  value: { language: 'en-US', languages: ['en-US'], userAgent: 'test' },
  configurable: true, writable: true
});
i18n.setLocale(devInfo.detectLanguage().supported);
ok(i18n.t('login') === 'Log in', 'nach Umschalten auf en-US liefert t(\'login\') den englischen Text');
ok(devInfo.guessDialCode() === '+1', 'Vorwahl für US-Englisch korrekt');
i18n.setLocale('de'); // Zustand für eventuelle Folgetests zurücksetzen

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
