# BWH Reality

BandwagonHost (camp-bwh) 运行 xray-core + VLESS-Reality-Vision，作为 camp-bb 的代理出口。

## 架构

```
camp-bb (Arch, 客户端)                       camp-bwh (Ubuntu 26.04, BWH CN2 GIA)
┌──────────────────────────┐                ┌───────────────────────────────┐
│  TUN → route → proxy-out ┼── VLESS ──────→│  xray Reality inbound :443      │
│       (sing-box)          │  Reality       │       │                        │
│                           │  flow: vision  │       ▼                        │
│  curl → mixed :8001 ──────┤                │  freedom outbound → internet   │
└──────────────────────────┘                └───────────────────────────────┘
                                            exit IP: 74.82.195.4
```

- **协议**：VLESS + Reality + Vision (`xtls-rprx-vision`)
- **伪装**：TLS 握手借 `www.apple.com` 证书，流量对 GFW 呈现为正常 Apple HTTPS
- **端口**：443（伪装成标准 HTTPS）
- **出口**：camp-bwh 直连 internet，不走 Tailscale

## 与旧 relay 方案的对比

| | 旧 (mt3000-st relay) | 新 (BWH Reality) |
|---|---|---|
| 传输 | Tailscale WireGuard | Reality 直连 |
| 中间跳 | camp-bb → tailscale → mt3000-st | camp-bb → camp-bwh |
| 加密层 | WG + VLESS 双层 | Reality 单层（伪装） |
| 端口 | 48443/48444 | 443 |
| 伪装 | 无（WG 指纹可识别） | 有（Apple TLS 证书） |

camp-box 仍使用旧 relay 方案（走 mt3000-st），两者独立。

## 部署

### 首次部署服务器

```bash
pyinfra inventory.py setup_bwh.py --limit camp-bwh -y
```

脚本会依次：

1. 安装 fail2ban（SSH 爆破保护） + curl + unzip
2. 安装 xray-core（官方脚本，幂等跳过）
3. `setcap cap_net_bind_service=+ep`（允许 nobody 用户绑 443）
4. 生成 Reality x25519 keypair + UUID，写入 `/usr/local/etc/xray/config.json`
5. 拉取客户端密钥到本地 `.camp-bwh-keys.json`
6. 配置 fail2ban SSH jail
7. 启用 BBR 拥塞控制
8. 开放防火墙 443（如 ufw 可用）

### 重新部署（幂等）

同一命令可重复执行。已完成的步骤自动跳过（No changes）：

```
Install Xray-core via official script          No change
Generate Reality keys and write xray config    No change
Fetch client keys from server                  No change
```

密钥只生成一次。除非删除 `/usr/local/etc/xray/config.json`，否则不会重新生成。

### 部署客户端

```bash
pyinfra inventory.py deploy.py --limit camp-bb -y
```

camp-bb 的 `config.yaml` 已配置好 `bwh_reality_outbound`：

```yaml
bwh_reality_outbound: &bwh_reality_outbound
  - _group: [proxy-out, ai-out]
    type: vless
    tag: camp-bwh
    server: "74.82.195.4"
    server_port: 443
    uuid: "<生成值>"
    flow: xtls-rprx-vision
    tls:
      enabled: true
      server_name: www.apple.com
      utls:
        enabled: true
        fingerprint: chrome
      reality:
        enabled: true
        public_key: "<生成值>"
        short_id: ""
```

`proxy-out` 和 `ai-out` 均指向 camp-bwh，所有流量通过 Reality 隧道出口。

## 密钥管理

密钥在服务端首次部署时生成，本地缓存于 `.camp-bwh-keys.json`（已 gitignore）。

| 密钥 | 位置 | 用途 |
|------|------|------|
| x25519 private key | `/usr/local/etc/xray/config.json` | 服务端，**机密** |
| x25519 public key | `.camp-bwh-keys.json` → `config.yaml` | 客户端认证 |
| UUID | 双方 | 客户端认证 |

xray v26 的 `x25519` 命令输出格式（注意与旧版不同）：

```
PrivateKey: <base64>
Password (PublicKey): <base64>
```

## xray 服务管理

```bash
# 状态
systemctl status xray

# 重启
systemctl restart xray

# 日志
journalctl -u xray -f

# 验证配置
xray run -c /usr/local/etc/xray/config.json -test
```

服务以 `nobody` 用户运行。通过 `setcap cap_net_bind_service=+ep` 获得绑定 443 的权限，无需以 root 运行。

## 验证

### 基本连通性

```bash
# camp-bb 上通过 SOCKS5 测试
curl -x socks5h://127.0.0.1:8001 -m 10 -s -o /dev/null -w "%{http_code} %{time_total}s\n" https://www.google.com

# 确认出口 IP
curl -x socks5h://127.0.0.1:8001 -m 10 -s https://api.ipify.org
# → 74.82.195.4
```

### 服务端端口确认

```bash
ssh camp-bwh 'ss -tlnp | grep 443'
# → LISTEN  *:443  users:(("xray",pid=...,fd=3))
```

### 常见问题

**443 未监听**：xray 以 nobody 运行但 `setcap` 未生效，重跑 `setcap cap_net_bind_service=+ep /usr/local/bin/xray && systemctl restart xray`。

**curl 返回 `(5) cannot complete SOCKS5 connection`**：sing-box 的 Reality outbound 连接失败。检查 camp-bwh 端口 443 是否可达（`curl -vk https://74.82.195.4:443` 应收到 TLS 握手，非 Reality 客户端会收到 RST，这是**正常的**）。

**Reality 警告**：`Choosing apple, icloud, etc. as the target may get your IP blocked by Apple`。仅警告，不影响功能。如需避免，可换用 `www.microsoft.com` 作为 dest。

**SSH 被 fail2ban 封禁**：`maxretry = 3, bantime = 3600`。通过 BWH 控制台或等 1 小时后自动解封。

## 配置常量

| 参数 | 值 | 说明 |
|------|-----|------|
| `LISTEN_PORT` | 443 | Reality 监听端口 |
| `REALITY_DEST` | `www.apple.com:443` | 伪装目标 |
| `SERVER_NAMES` | `www.apple.com`, `apple.com` | SNI 白名单 |
| `flow` | `xtls-rprx-vision` | Vision 流控 |
| `utls.fingerprint` | `chrome` | 客户端 TLS 指纹 |
