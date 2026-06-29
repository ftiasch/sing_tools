"""
Setup BandwagonHost VPS with Xray-core + VLESS-Reality-Vision.

Usage:
    pyinfra inventory.py setup_bwh.py --limit camp-bwh -y

Idempotent: safe to run repeatedly. Keys are generated on first run and
saved to .camp-bwh-keys.json locally for client configuration.
"""

from io import StringIO

from pyinfra import host, logger
from pyinfra.facts.files import File
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server, systemd

# ── Constants ──────────────────────────────────────────────────────────
XRAY_CONFIG_DIR = "/usr/local/etc/xray"
XRAY_CONFIG_PATH = f"{XRAY_CONFIG_DIR}/config.json"
SERVER_KEYS_PATH = "/root/.xray-client-keys.json"
LOCAL_KEYS_PATH = ".camp-bwh-keys.json"

REALITY_DEST = "www.apple.com:443"
LISTEN_PORT = 443

# ── Step 1: System packages ────────────────────────────────────────────

apt.packages(
    name="Install fail2ban and prerequisites",
    packages=["fail2ban", "curl", "unzip"],
    update=True,
    _sudo=True,
)

# ── Step 2: Install Xray-core ──────────────────────────────────────────
server.shell(
    name="Install Xray-core via official script",
    commands=[
        'bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install'
    ],
    _sudo=True,
    _if=lambda: host.get_fact(Which, command="xray") is None,
)

# xray systemd service runs as nobody; grant CAP_NET_BIND_SERVICE so it
# can bind privileged port 443 without running as root.
server.shell(
    name="Grant xray CAP_NET_BIND_SERVICE capability",
    commands=["setcap cap_net_bind_service=+ep /usr/local/bin/xray"],
    _sudo=True,
)

# ── Step 3: Generate keys & write config (idempotent) ──────────────────

gen_config_script = f"""#!/bin/bash
set -euo pipefail

CONFIG_DIR="{XRAY_CONFIG_DIR}"
CONFIG_FILE="{XRAY_CONFIG_PATH}"
KEYS_FILE="{SERVER_KEYS_PATH}"
LISTEN_PORT={LISTEN_PORT}
REALITY_DEST="{REALITY_DEST}"
SERVER_NAMES='["www.apple.com", "apple.com"]'

if [ -f "${{CONFIG_FILE}}" ] && [ -s "${{CONFIG_FILE}}" ]; then
    echo "Xray config already exists, validating..."
    xray run -c "${{CONFIG_FILE}}" -test && echo "Config valid, skipping generation."
    exit 0
fi

echo "Generating Reality keys..."
mkdir -p "${{CONFIG_DIR}}"

KEYS=$(xray x25519 2>&1)
PRIVATE_KEY=$(echo "${{KEYS}}" | awk -F': ' '/PrivateKey:/ {{print $2}}')
PUBLIC_KEY=$(echo "${{KEYS}}" | awk -F': ' '/Password/ {{print $2}}')
UUID=$(cat /proc/sys/kernel/random/uuid)

echo "Private key: ${{PRIVATE_KEY}}"
echo "Public key:  ${{PUBLIC_KEY}}"
echo "UUID:        ${{UUID}}"

cat > "${{CONFIG_FILE}}" <<'XRAYEOF'
{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [
    {{
      "port": LISTEN_PORT_PH,
      "protocol": "vless",
      "settings": {{
        "clients": [
          {{
            "id": "UUID_PH",
            "flow": "xtls-rprx-vision",
            "email": "camp-bb"
          }}
        ],
        "decryption": "none"
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "show": false,
          "dest": "DEST_PH",
          "xver": 0,
          "serverNames": SERVER_NAMES_PH,
          "privateKey": "PRIVATE_KEY_PH",
          "shortIds": [""]
        }}
      }},
      "sniffing": {{
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }}
    }}
  ],
  "outbounds": [
    {{ "protocol": "freedom", "tag": "direct" }},
    {{ "protocol": "blackhole", "tag": "block" }}
  ],
  "routing": {{
    "rules": [
      {{ "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }},
      {{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }}
    ]
  }}
}}
XRAYEOF

sed -i "s|LISTEN_PORT_PH|${{LISTEN_PORT}}|g" "${{CONFIG_FILE}}"
sed -i "s|UUID_PH|${{UUID}}|g" "${{CONFIG_FILE}}"
sed -i "s|DEST_PH|${{REALITY_DEST}}|g" "${{CONFIG_FILE}}"
sed -i "s|SERVER_NAMES_PH|${{SERVER_NAMES}}|g" "${{CONFIG_FILE}}"
sed -i "s|PRIVATE_KEY_PH|${{PRIVATE_KEY}}|g" "${{CONFIG_FILE}}"

cat > "${{KEYS_FILE}}" <<EOF
{{"uuid": "${{UUID}}", "public_key": "${{PUBLIC_KEY}}", "dest": "${{REALITY_DEST}}"}}
EOF

echo "Keys saved to ${{KEYS_FILE}}"
echo "Server config written to ${{CONFIG_FILE}}"
"""
server.shell(
    name="Generate Reality keys and write xray config",
    commands=[gen_config_script],
    _sudo=True,
    _if=lambda: host.get_fact(File, path="/usr/local/etc/xray/config.json") is None,
)


# ── Step 3b: Fetch client keys back to local machine ───────────────────

files.get(
    name="Fetch client keys from server",
    src=SERVER_KEYS_PATH,
    dest=LOCAL_KEYS_PATH,
    _sudo=True,
)

# ── Step 4: Configure fail2ban for SSH ─────────────────────────────────

fail2ban_jail_local = """[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600
findtime = 600
"""

files.put(
    name="Configure fail2ban SSH jail",
    src=StringIO(fail2ban_jail_local),
    dest="/etc/fail2ban/jail.local",
    _sudo=True,
)

# ── Step 5: Enable BBR congestion control ──────────────────────────────

bbr_conf = """net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
"""

files.put(
    name="Enable BBR congestion control",
    src=StringIO(bbr_conf),
    dest="/etc/sysctl.d/99-bbr.conf",
    _sudo=True,
)

server.shell(
    name="Apply BBR sysctl",
    commands=["sysctl -p /etc/sysctl.d/99-bbr.conf"],
    _sudo=True,
)

# ── Step 6: Firewall — open Reality port ───────────────────────────────

server.shell(
    name="Allow port 443 through ufw",
    commands=["ufw allow 443/tcp"],
    _sudo=True,
    _ignore_errors=True,
)

# ── Step 7: Enable & start services ────────────────────────────────────

systemd.service(
    name="Enable and start xray",
    service="xray",
    running=True,
    enabled=True,
    _sudo=True,
)

systemd.service(
    name="Enable and start fail2ban",
    service="fail2ban",
    running=True,
    enabled=True,
    _sudo=True,
)

# ── Step 8: Validate server config ─────────────────────────────────────

server.shell(
    name="Validate xray config",
    commands=["xray run -c /usr/local/etc/xray/config.json -test"],
    _sudo=True,
)

# ── Summary ────────────────────────────────────────────────────────────

logger.info("=" * 50)
logger.info("BWH Reality server setup complete!")
logger.info(f"Client keys saved to: {LOCAL_KEYS_PATH}")
logger.info("Run the following to see client keys:")
logger.info(f"  cat {LOCAL_KEYS_PATH}")
logger.info("=" * 50)
