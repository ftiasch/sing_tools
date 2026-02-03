# Project Overview

## Purpose

This is a **sing-box configuration management and deployment tool** that automates the generation and deployment of sing-box proxy configurations across multiple hosts.

## Architecture

### Components

- **`app.py`**: Main CLI application for downloading subscriptions and generating configurations
- **`deploy.py`**: Pyinfra deployment script that uploads generated configs to remote hosts and restarts services
- **`inventory.py`**: Pyinventory loader that reads hosts from `config.yaml`
- **`config.yaml`**: Central configuration file defining providers, hosts, and their outbounds
- **`templates/`**: Directory containing per-host configuration templates (base.yaml + host-specific yaml files)
- **`db.json`**: Local cache of downloaded subscription data

### Workflow

```
1. Download: app.py download [provider]
   → Fetches proxy subscriptions from providers
   → Stores in db.json cache

2. Generate: app.py generate <host>
   → Reads host config from config.yaml
   → Merges base template + host template
   → Parses subscriptions from db.json
   → Generates sing-box config.json

3. Deploy: pyinfra inventory.py deploy.py
   → Generates config for each host
   → Uploads to /etc/sing-box/config.json
   → Restarts sing-box service
```

## Configuration Structure

### config.yaml

```yaml
db_path: ./db.json
timeout: 10
providers:
  provider_name:
    url: https://...
    ua: "user-agent"
    paramiko:
      host: proxy-host  # Optional: download via SSH
hosts:
  base: &base
    type: sing
    sudo: false
  hostname:
    <<: *base
    outbounds:
      - provider_name
    sudo: true  # Whether to use sudo for service restart
```

### Template System

- **`templates/base.yaml`**: Base sing-box configuration (DNS, routes, etc.)
- **`templates/{host}.yaml`**: Host-specific overrides (custom rules, etc.)
- Templates are merged using `dict_merge()` function
- Jinja2 blocks can be used for conditional logic

## Supported Proxy Types

The system parses and converts various proxy URL formats to sing-box configuration:

- **ss://** (Shadowsocks)
- **trojan://** (Trojan)
- **vless://** (VLESS with Vision/WS transport)
- **vmess://** (VMess with WS transport)
- **sing-box JSON configs** (direct import from sing-box format)

## Subscription Sources

Subscriptions can be downloaded:
- **Direct HTTP**: Using curl with custom user-agent
- **Via SSH proxy**: Using paramiko to tunnel downloads through another host

## Proxy Grouping

Proxies are automatically grouped by region:
- **HK/Hong Kong**: `hk-out`
- **JP/Japan**: `jp-out`
- **US/United States**: `us-out`
- **RU/Russia**: Excluded (filtered out)

## Target Hosts

Supports deployment to different Linux distributions:
- **Arch Linux** (systemd-managed sing-box)
- **OpenWrt/ImmortalWrt** (procd-managed sing-box via init scripts)

### Host Configuration Variations

**Standard Linux (e.g., Arch):**
- Config path: `/etc/sing-box/config.json`
- Service: `systemctl restart sing-box`
- SFTP: Usually available (OpenSSH)

**OpenWrt/ImmortalWrt:**
- Config path: `/etc/sing-box/config.json`
- Service: `/etc/init.d/sing-box restart`
- Service management: procd (via UCI configuration)
- SSH: Often uses Dropbear (limited SFTP support)
- Enable requirement: Service must be enabled via `uci set sing-box.main.enabled=1`

## Development Commands

```bash
# Download subscriptions
uv run app.py download [provider_regex]

# Generate config for specific host
uv run app.py generate <hostname>

# Deploy to all hosts
uv run pyinfra inventory.py -y deploy.py

# Deploy to specific host
uv run pyinfra inventory.py --limit <hostname> -y deploy.py
```

## Key Dependencies

- **pyinfra**: Remote execution and deployment automation
- **pydantic**: Configuration validation
- **typer**: CLI framework
- **paramiko**: SSH client for proxied downloads
- **PyYAML**: YAML configuration parsing

## Important Notes

1. **Templates required**: Each host must have a corresponding `templates/{host}.yaml` file
2. **SFTP limitation**: OpenWrt systems using Dropbear SSH don't support SFTP, breaking pyinfra's file transfer
3. **Service enablement**: On OpenWrt, services must be enabled via UCI before they will start
4. **Subscription caching**: Downloaded subscriptions are cached in `db.json` to avoid re-downloading
5. **Region filtering**: Russian (RU) proxies are automatically excluded from configurations
