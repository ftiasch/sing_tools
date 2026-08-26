"""
Deploy the BWH sing-box Reality server on a fresh machine.

Single idempotent flow using pyinfra standard operations: apt install,
download + unpack the release tarball, write the systemd unit, generate
the server config from the shared client credentials, validate with
`sing-box check`, enable + start the service. No cutover, no rollback.

The server must reuse the existing credentials so clients keep working:
- UUID comes from config.yaml (single source of truth).
- The Reality private key is NOT stored in this repo; pass it via the
  BWH_PRIVATE_KEY environment variable. Get it from the current server:
  `jq -r .inbounds[0].tls.reality.private_key /etc/sing-box/config.json`

Usage (run from repo root, requires venv pyinfra). camp-bwh is defined in
config.yaml with its SSH details, so the inventory connector works:

    BWH_PRIVATE_KEY=... uv run pyinfra inventory.py --limit camp-bwh -y deploy_bwh_sing.py

The private key travels over the encrypted SSH connection (SFTP for the
config upload); it never touches local disk or the pyinfra command text.
"""

import json
import os
from io import StringIO

import yaml

from pyinfra import logger
from pyinfra.context import host
from pyinfra.facts.files import File
from pyinfra.operations import apt, files, iptables, server, systemd

# ── Credentials ────────────────────────────────────────────────────────

PRIVATE_KEY = os.environ.get("BWH_PRIVATE_KEY", "").strip()
if not PRIVATE_KEY:
    raise SystemExit(
        "BWH_PRIVATE_KEY env var is required: "
        "the server Reality private key (see module docstring)"
    )

# UUID from config.yaml (single source of truth, shared with clients).
config = yaml.safe_load(open("config.yaml", encoding="utf-8"))
UUID = os.environ.get("BWH_UUID", "").strip() or config["bwh_reality_outbound"][0]["uuid"]

# ── Constants ──────────────────────────────────────────────────────────
SING_VERSION = "1.13.19"
SING_TAR_URL = (
    f"https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SING_VERSION}/sing-box-{SING_VERSION}-linux-amd64.tar.gz"
)
SING_TAR = f"/tmp/sing-box-{SING_VERSION}-linux-amd64.tar.gz"
SING_UNPACKED = f"/tmp/sing-box-{SING_VERSION}-linux-amd64"
SING_BIN = "/usr/local/bin/sing-box"
SING_DIR = "/etc/sing-box"
SING_CONFIG = f"{SING_DIR}/config.json"
SING_UNIT = "/etc/systemd/system/sing-box.service"

SERVER_NAME = "www.apple.com"  # Reality SNI + handshake target
LISTEN_PORT = 443

# ── Step 1: System packages ────────────────────────────────────────────

apt.packages(
    name="Install fail2ban and curl",
    packages=["fail2ban", "curl"],
    update=True,
    _sudo=True,
)

# ── Step 2: Install sing-box from the official release tarball ─────────

files.download(
    name="Download sing-box release tarball",
    src=SING_TAR_URL,
    dest=SING_TAR,
    _sudo=True,
    _if=lambda: host.get_fact(File, path=SING_BIN) is None,
)

# Unpack and install the binary. pyinfra 3.6.1 has no unarchive op, so a
# single shell command is required here.
server.shell(
    name="Unpack tarball and install sing-box binary",
    commands=[
        f"tar -xzf {SING_TAR} -C /tmp && "
        f"install -m755 {SING_UNPACKED}/sing-box {SING_BIN} && "
        f"rm -rf {SING_UNPACKED} {SING_TAR}"
    ],
    _sudo=True,
    _if=lambda: host.get_fact(File, path=SING_BIN) is None,
)

# ── Step 3: systemd unit (nobody + CAP_NET_BIND_SERVICE) ───────────────

sing_unit = f"""[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart={SING_BIN} run -c {SING_CONFIG}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
"""

files.put(
    name="Write sing-box systemd unit",
    src=StringIO(sing_unit),
    dest=SING_UNIT,
    _sudo=True,
)

systemd.daemon_reload(
    name="Reload systemd daemon",
    _sudo=True,
)

# ── Step 4: Generate server config, validate, install ──────────────────

server_config = {
    "log": {"level": "info", "timestamp": True},
    "inbounds": [
        {
            "type": "vless",
            "tag": "reality-in",
            "listen": "::",
            "listen_port": LISTEN_PORT,
            "users": [
                {
                    "name": "camp-bb",
                    "uuid": UUID,
                    "flow": "xtls-rprx-vision",
                }
            ],
            "tls": {
                "enabled": True,
                "server_name": SERVER_NAME,
                "reality": {
                    "enabled": True,
                    "handshake": {
                        "server": SERVER_NAME,
                        "server_port": LISTEN_PORT,
                    },
                    "private_key": PRIVATE_KEY,
                    "short_id": [""],
                },
            },
        }
    ],
    "outbounds": [{"type": "direct", "tag": "direct"}],
    "route": {
        "rules": [
            {"action": "sniff"},
            {"action": "reject", "protocol": ["bittorrent"]},
        ],
        "final": "direct",
    },
}

files.put(
    name="Write sing-box server config",
    src=StringIO(json.dumps(server_config, indent=2)),
    dest=SING_CONFIG,
    _sudo=True,
)

# Validate the generated config (no standard op can run it).
server.shell(
    name="Validate sing-box config",
    commands=[f"{SING_BIN} check -c {SING_CONFIG}"],
    _sudo=True,
)

# ── Step 5: fail2ban SSH jail ──────────────────────────────────────────

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

# ── Step 6: Enable BBR congestion control ──────────────────────────────

server.sysctl(
    name="Enable fq qdisc",
    key="net.core.default_qdisc",
    value="fq",
    persist=True,
    persist_file="/etc/sysctl.d/99-bbr.conf",
    _sudo=True,
)

server.sysctl(
    name="Enable BBR congestion control",
    key="net.ipv4.tcp_congestion_control",
    value="bbr",
    persist=True,
    persist_file="/etc/sysctl.d/99-bbr.conf",
    _sudo=True,
)

# ── Step 7: Firewall — open Reality port ───────────────────────────────

iptables.rule(
    name=f"Allow {LISTEN_PORT}/tcp",
    chain="INPUT",
    jump="ACCEPT",
    protocol="tcp",
    destination_port=LISTEN_PORT,
    _sudo=True,
)

# ── Step 8: Enable & start sing-box ────────────────────────────────────

systemd.service(
    name="Enable and start sing-box",
    service="sing-box",
    running=True,
    enabled=True,
    _sudo=True,
)

logger.info("BWH sing-box server deployed.")
