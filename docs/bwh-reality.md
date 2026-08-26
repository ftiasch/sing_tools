# BWH Reality

BandwagonHost (camp-bwh) 运行 sing-box + VLESS-Reality-Vision，作为 camp-bb / camp-box 的代理出口。2026-08 从 xray-core 迁移而来，凭据完全复用，客户端零变更。

## 架构

```
camp-bb / camp-box (客户端)                  camp-bwh (Ubuntu 26.04, BWH CN2 GIA)
┌──────────────────────────┐                ┌───────────────────────────────┐
│  TUN → route → proxy-out ┼── VLESS ──────→│  sing-box Reality inbound :443 │
│       (sing-box)          │  Reality       │       │                        │
│                           │  flow: vision  │       ▼                        │
│  curl → mixed :8001 ──────┤                │  direct outbound → internet    │
└──────────────────────────┘                └───────────────────────────────┘
                                            exit IP: SERVER_IP
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

camp-box 使用同一 BWH 出口（`bwh_reality_outbound`），与 camp-bb 独立。

## 部署

### 部署服务端（新机器）

单命令幂等流程：安装 sing-box 1.13.19、写 systemd unit、生成服务端配置、`sing-box check` 校验、enable + start。可安全重复执行。

```bash
BWH_PRIVATE_KEY=... uv run pyinfra inventory.py --limit camp-bwh -y deploy_bwh_sing.py
```

服务端必须复用现有凭据，客户端才能零变更继续工作：

- **UUID**：从 `config.yaml` 的 `bwh_reality_outbound` 读取（仓库内单一事实源）。
- **Reality private key**：不入库，通过 `BWH_PRIVATE_KEY` 环境变量传入。从当前服务器提取：

  ```bash
  ssh root@SERVER_IP "python3 -c \"import json; print(json.load(open('/etc/sing-box/config.json'))['inbounds'][0]['tls']['reality']['private_key'])\""
  ```

  私钥经加密 SSH 连接以远端环境变量传递，不落本地磁盘。

- **SNI / dest**：固定 `www.apple.com`；**short ID**：空；**flow**：`xtls-rprx-vision`。

脚本还会配置 fail2ban SSH jail、BBR 拥塞控制与防火墙 443。

### 部署客户端

```bash
uv run pyinfra inventory.py --limit camp-bb -y deploy.py
```

`config.yaml` 中 `bwh_reality_outbound` 定义客户端 outbound：

```yaml
bwh_reality_outbound: &bwh_reality_outbound
  - _group: [proxy-out, ai-out]
    type: vless
    tag: camp-bwh
    server: "SERVER_IP"
    server_port: 443
    uuid: "1870c1a3-cd84-4e91-aac6-551b143e8ed6"
    flow: xtls-rprx-vision
    tls:
      enabled: true
      server_name: www.apple.com
      utls:
        enabled: true
        fingerprint: chrome
      reality:
        enabled: true
        public_key: "lt2OkFkaGBkQPKvnzfjVFZQOUrBwkkkvt_1GvQp58Qo"
        short_id: ""
```

`proxy-out` 和 `ai-out` 均指向 camp-bwh，所有流量通过 Reality 隧道出口。

## 密钥管理

服务端 Reality private key 存于 `/etc/sing-box/config.json`（服务端，**机密**），部署时经 `BWH_PRIVATE_KEY` 环境变量写入，不入库。客户端密钥缓存于本地 `.camp-bwh-keys.json`（已 gitignore）。

| 密钥 | 位置 | 用途 |
|------|------|------|
| x25519 private key | `/etc/sing-box/config.json` | 服务端，**机密** |
| x25519 public key | `.camp-bwh-keys.json` → `config.yaml` | 客户端认证 |
| UUID | 双方 | 客户端认证 |

## sing-box 服务管理

```bash
# 状态
systemctl status sing-box

# 重启
systemctl restart sing-box

# 日志
journalctl -u sing-box -f

# 验证配置
sing-box check -c /etc/sing-box/config.json
```

服务以 `nobody` 用户运行，systemd unit 授予 `CAP_NET_BIND_SERVICE` 绑定 443。

## 验证

### 基本连通性

```bash
# camp-bb 上通过 SOCKS5 测试
curl -x socks5h://127.0.0.1:8001 -m 10 -s -o /dev/null -w "%{http_code} %{time_total}s\n" https://www.google.com

# 确认出口 IP
curl -x socks5h://127.0.0.1:8001 -m 10 -s https://api.ipify.org
# → SERVER_IP
```

### 服务端端口确认

```bash
ssh root@SERVER_IP 'ss -tlnp | grep 443'
# → LISTEN  *:443  users:(("sing-box",pid=...,fd=...))
```

### 常见问题

**443 未监听**：sing-box 以 nobody 运行但 `CAP_NET_BIND_SERVICE` 未生效，检查 `/etc/systemd/system/sing-box.service` 的 `AmbientCapabilities` 后 `systemctl daemon-reload && systemctl restart sing-box`。

**curl 返回 `(5) cannot complete SOCKS5 connection`**：sing-box 的 Reality outbound 连接失败。检查 camp-bwh 端口 443 是否可达（`curl -vk https://SERVER_IP:443` 应收到 TLS 握手，非 Reality 客户端会收到 RST，这是**正常的**）。

**SSH 被 fail2ban 封禁**：`maxretry = 3, bantime = 3600`。通过 BWH 控制台或等 1 小时后自动解封；tailscale 通道（`root@TAILSCALE_IP`）不受影响。

## 配置常量

| 参数 | 值 | 说明 |
|------|-----|------|
| `listen_port` | 443 | Reality 监听端口 |
| `handshake.server` | `www.apple.com:443` | 伪装目标 |
| `server_name` | `www.apple.com` | SNI 白名单 |
| `flow` | `xtls-rprx-vision` | Vision 流控 |
| `utls.fingerprint` | `chrome` | 客户端 TLS 指纹 |
