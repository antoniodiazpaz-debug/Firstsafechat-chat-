/* Node-ESM-Loader-Hook: bildet absolute Importpfade wie "/crypto-core.js"
   (wie sie im Browser relativ zur Domain aufgelöst werden) auf das
   lokale public/-Verzeichnis ab. Nur für Tests — im Browser braucht es
   das nicht, dort ist "/crypto-core.js" bereits korrekt.

   Query-Strings (z. B. "/app.js?client=alice") werden VOR dem
   Pfad-Mapping abgetrennt und danach wieder angehängt — Tests nutzen
   sie bewusst, um denselben Modulpfad mehrfach mit eigenem Zustand zu
   laden (Node cached ESM-Module sonst pro exakter URL). */
import { pathToFileURL } from 'node:url';
import path from 'node:path';

const PUBLIC_DIR = path.resolve(import.meta.dirname, '..', 'public');

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith('/') && !specifier.startsWith('//')) {
    const qIndex = specifier.indexOf('?');
    const cleanPath = qIndex === -1 ? specifier : specifier.slice(0, qIndex);
    const query = qIndex === -1 ? '' : specifier.slice(qIndex);
    const filePath = path.join(PUBLIC_DIR, cleanPath);
    return nextResolve(pathToFileURL(filePath).href + query, context);
  }
  return nextResolve(specifier, context);
}
