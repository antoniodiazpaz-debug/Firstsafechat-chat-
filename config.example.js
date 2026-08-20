/* Lokale Entwicklungskonfiguration.
   In Produktion wird diese Datei vom Deploy-Workflow erzeugt
   (siehe .github/workflows/deploy.yml), nicht von Hand gepflegt. */
window.SECURECHAT_CONFIG = {
  supabaseUrl: '',
  supabaseAnonKey: '',
  mixDirectoryUrl: ''
};

/* R2-Medienspeicher. {path} wird durch den zufälligen Dateinamen ersetzt.
   Ohne diese Konfiguration bleibt der Text-/Ratchet-Pfad voll nutzbar —
   nur der Versand großer Medien (>6 KB) ist dann deaktiviert. */
window.MEDIA_CONFIG = {
  uploadUrl: '',    // z. B. 'https://media.example.com/upload/{path}'
  downloadUrl: ''   // z. B. 'https://media.example.com/{path}'
};
