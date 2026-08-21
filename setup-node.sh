#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Mix-Knoten auf einer frischen VM einrichten
# ═══════════════════════════════════════════════════════════════════════
# Getestet auf Ubuntu 22.04/24.04 ARM und x86 (Oracle Always Free,
# Hetzner, jede andere Linux-VM).
#
#   curl -fsSL <raw-url>/setup-node.sh | sudo bash -s -- mix-eu https://…
#
# Argumente:
#   $1  NODE_ID       z. B. mix-eu
#   $2  DELIVER_URL   Zustelladresse (leer = reiner Zwischenknoten)
#   $3  DELIVER_AUTH  gemeinsames Geheimnis für die Zustellung
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

NODE_ID="${1:?NODE_ID fehlt, z. B. mix-eu}"
DELIVER_URL="${2:-}"
DELIVER_AUTH="${3:-}"
PORT="${PORT:-8080}"
DIR=/opt/securechat

echo "══ Mix-Knoten $NODE_ID einrichten ══"

# ── Node 22: node:sqlite und WebCrypto brauchen mindestens 22.5 ──
if ! command -v node >/dev/null || \
   [ "$(node -p 'process.versions.node.split(".").map(Number)[0]')" -lt 22 ]; then
  echo "→ Node 22 installieren"
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi
node --version

# ── Eigener Benutzer ohne Login-Shell ──
id -u securechat >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home "$DIR" securechat
mkdir -p "$DIR/data"
chown -R securechat:securechat "$DIR"
chmod 700 "$DIR/data"        # hier liegt der private Knotenschlüssel

# ── systemd-Dienst ──
cat > /etc/systemd/system/securechat-mix.service <<EOF
[Unit]
Description=SecureChat Mix-Knoten ($NODE_ID)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=securechat
WorkingDirectory=$DIR
ExecStart=/usr/bin/node $DIR/mix-node.js
Restart=always
RestartSec=5

Environment=NODE_ID=$NODE_ID
Environment=PORT=$PORT
Environment=KEY_FILE=$DIR/data/mixkey.json
Environment=DIRECTORY=$DIR/data/directory.json
$( [ -n "$DELIVER_URL" ]  && echo "Environment=DELIVER_URL=$DELIVER_URL" )
$( [ -n "$DELIVER_AUTH" ] && echo "Environment=DELIVER_AUTH=$DELIVER_AUTH" )

# Absicherung: Der Knoten braucht fast nichts vom System
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DIR/data
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

# ── Deploy-Benutzer darf genau diesen einen Dienst neu starten ──
cat > /etc/sudoers.d/securechat-deploy <<EOF
%sudo ALL=(root) NOPASSWD: /bin/systemctl restart securechat-mix
%sudo ALL=(root) NOPASSWD: /bin/systemctl is-active securechat-mix
EOF
chmod 440 /etc/sudoers.d/securechat-deploy

# ── Firewall: nur der Knotenport nach außen ──
if command -v ufw >/dev/null; then
  ufw allow "$PORT"/tcp >/dev/null 2>&1 || true
fi
# Oracle-VMs haben zusätzlich iptables-Regeln, die alles blocken
if command -v iptables >/dev/null; then
  iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
  command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
fi

systemctl daemon-reload
systemctl enable securechat-mix >/dev/null

echo
echo "══ Fertig ══"
echo "  Dateien nach $DIR kopieren:  mixnet.js  mix-node.js"
echo "  Dann:  systemctl start securechat-mix"
echo
echo "  Öffentlichen Schlüssel abrufen:  curl localhost:$PORT/info"
echo "  In der Oracle-Konsole zusätzlich Port $PORT in der Security List öffnen."
