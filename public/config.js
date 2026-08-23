/* Produktionskonfiguration für SecureChat auf Fly.io.
   apiBase bleibt leer, weil Client und Server auf derselben Domain
   laufen (https://firstsafechatsserver.fly.dev) — api-client.js fällt
   dann automatisch auf location.origin zurück, siehe app.js Zeile 43. */
window.SECURECHAT_CONFIG = {
  apiBase: ''
};

/* Medien-Uploads laufen über die serverseitigen Presigned-URL-Routen
   (/api/media/upload-url, /api/media/download-url), nicht über eine
   fest hinterlegte externe Adresse — media-storage.js fragt die
   jeweils gültige URL bei jedem Upload/Download direkt beim Server ab.
   Diese Variablen bleiben deshalb bewusst leer. */
window.MEDIA_CONFIG = {
  uploadUrl: '',
  downloadUrl: ''
};
