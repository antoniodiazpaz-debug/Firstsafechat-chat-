/* ═══════════════════════════════════════════════════════════════════════
   I18N — minimale Übersetzungstabelle
   ─────────────────────────────────────────────────────────────────────
   Bewusst schlank: nur die Strings, die beim Boot/Auth-Flow sichtbar
   sind. Weitere Sprachen/Strings werden ergänzt, sobald die restliche
   UI (Chat-Fenster, Einstellungen) steht — eine vollständige Tabelle
   jetzt zu bauen hieße, Übersetzungen für UI zu schreiben, die sich
   noch ändert.
   ═══════════════════════════════════════════════════════════════════════ */
const STRINGS = {
  de: {
    appName: 'SecureChat', tagline: 'Ende-zu-Ende verschlüsselt · X3DH · Double Ratchet',
    login: 'Anmelden', register: 'Registrieren', createAccount: 'Konto erstellen',
    username: 'Benutzername', password: 'Passwort', phone: 'Telefonnummer (optional)',
    email: 'E-Mail (optional)', unlock: 'Entsperren', otherAccount: 'Anderes Konto',
    welcomeBack: 'Willkommen zurück', newDevice: 'Neues Gerät',
    pairHint: 'Öffne auf einem bereits angemeldeten Gerät: Profil → Geräte → „Gerät koppeln", und gib hier den angezeigten Code ein.',
    pairCode: 'Pairing-Code', pair: 'Koppeln', back: 'Zurück',
    fieldsRequired: 'Bitte alle Felder ausfüllen',
    passwordTooShort: 'Passwort braucht mindestens 8 Zeichen',
    phoneRequired: 'Telefonnummer erforderlich',
    generatingKeys: '🔐 Schlüssel werden erzeugt…',
    welcome: 'Willkommen',
    smsHint: 'Code kommt per SMS automatisch an, wenn dein Browser das unterstützt.'
  },
  en: {
    appName: 'SecureChat', tagline: 'End-to-end encrypted · X3DH · Double Ratchet',
    login: 'Log in', register: 'Sign up', createAccount: 'Create account',
    username: 'Username', password: 'Password', phone: 'Phone number (optional)',
    email: 'Email (optional)', unlock: 'Unlock', otherAccount: 'Different account',
    welcomeBack: 'Welcome back', newDevice: 'New device',
    pairHint: 'On a device you\u2019re already signed in on: Profile → Devices → "Link device", then enter the code shown there.',
    pairCode: 'Pairing code', pair: 'Link device', back: 'Back',
    fieldsRequired: 'Please fill in all fields',
    passwordTooShort: 'Password needs at least 8 characters',
    phoneRequired: 'Phone number required',
    generatingKeys: '🔐 Generating keys…',
    welcome: 'Welcome',
    smsHint: 'Code will be filled in automatically from SMS if your browser supports it.'
  },
  es: {
    appName: 'SecureChat', tagline: 'Cifrado de extremo a extremo · X3DH · Double Ratchet',
    login: 'Iniciar sesión', register: 'Registrarse', createAccount: 'Crear cuenta',
    username: 'Usuario', password: 'Contraseña', phone: 'Número de teléfono (opcional)',
    email: 'Correo (opcional)', unlock: 'Desbloquear', otherAccount: 'Otra cuenta',
    welcomeBack: 'Bienvenido de nuevo', newDevice: 'Nuevo dispositivo',
    pairHint: 'En un dispositivo donde ya iniciaste sesión: Perfil → Dispositivos → "Vincular dispositivo", luego introduce el código.',
    pairCode: 'Código de vinculación', pair: 'Vincular', back: 'Atrás',
    fieldsRequired: 'Completa todos los campos',
    passwordTooShort: 'La contraseña necesita al menos 8 caracteres',
    phoneRequired: 'Número de teléfono requerido',
    generatingKeys: '🔐 Generando claves…',
    welcome: 'Bienvenido',
    smsHint: 'El código se completará automáticamente por SMS si tu navegador lo permite.'
  },
  fr: {
    appName: 'SecureChat', tagline: 'Chiffré de bout en bout · X3DH · Double Ratchet',
    login: 'Connexion', register: 'Inscription', createAccount: 'Créer un compte',
    username: 'Nom d\u2019utilisateur', password: 'Mot de passe', phone: 'Numéro de téléphone (facultatif)',
    email: 'E-mail (facultatif)', unlock: 'Déverrouiller', otherAccount: 'Autre compte',
    welcomeBack: 'Content de vous revoir', newDevice: 'Nouvel appareil',
    pairHint: 'Sur un appareil déjà connecté : Profil → Appareils → « Associer un appareil », puis entrez le code affiché.',
    pairCode: 'Code d\u2019association', pair: 'Associer', back: 'Retour',
    fieldsRequired: 'Veuillez remplir tous les champs',
    passwordTooShort: 'Le mot de passe doit contenir au moins 8 caractères',
    phoneRequired: 'Numéro de téléphone requis',
    generatingKeys: '🔐 Génération des clés…',
    welcome: 'Bienvenue',
    smsHint: 'Le code sera rempli automatiquement par SMS si votre navigateur le prend en charge.'
  }
};

let current = 'de';
export function setLocale(lang) {
  current = STRINGS[lang] ? lang : 'de';
  return current;
}
export function getLocale() { return current; }
export function t(key) {
  return STRINGS[current]?.[key] ?? STRINGS.de[key] ?? key;
}
export const AVAILABLE_LOCALES = Object.keys(STRINGS);
