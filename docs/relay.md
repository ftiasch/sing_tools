# Sing-box Relay Chain

两台 sing-box 通过 vless 串流——B 的流量经 Tailscale 隧道转发到 A，由 A 的代理组出站。

## 架构

```
camp-pk (B, x86 Arch)                     mt3000-st (A, arm OpenWRT)
┌──────────────────────┐                 ┌─────────────────────────┐
│ http inbound         │                 │ vless inbound           │
│   test-in :9999      │                 │   relay-in :8443        │
│       │              │                 │       │                 │
│       ▼              │   vless/tcp     │       ▼                 │
│   relay-out ─────────┼──Tailscale──────┼──→ route → proxy-out ──→ internet
│   bind: tailscale0   │                 │   (urltest, dg)         │
│   → 100.116.175.64   │                 │                         │
└──────────────────────┘                 └─────────────────────────┘
```

- **B** 无 TUN，不直接出站。所有流量经 `relay-out` → A。
- **A** 的 `relay-in` 监听 Tailscale IP，收到流量后走自己的 route → proxy-out。
- Tailscale 提供 WireGuard 加密，vless 不加 TLS（`security: none`）。

## 配置

### A (mt3000-st) — `templates/mt3000-st.yaml`

```yaml
after_inbounds:
  - type: vless
    tag: relay-in
    listen: "100.116.175.64"
    listen_port: 8443
    users:
      - uuid: "b56dbbfd-639e-4e50-af16-a26d70e68480"
```

### B (camp-pk) — `templates/camp-pk.yaml`

```yaml
inbounds:
  - type: http
    tag: test-in
    listen: "127.0.0.1"
    listen_port: 9999
outbounds:
  - type: vless
    tag: relay-out
    server: "100.116.175.64"
    server_port: 8443
    uuid: "b56dbbfd-639e-4e50-af16-a26d70e68480"
    bind_interface: tailscale0
dns:
  servers:
    - tag: dns_proxy
      type: tls
      server: 8.8.8.8
      detour: relay-out
    - tag: dns_direct
      type: tls
      server: 223.5.5.5
    - tag: dns_tailscale
      type: udp
      server: 100.100.100.100
      detour: tailscale0-out
route:
  final: relay-out
```

B 用 `inbounds`（替换 base 的 TUN+mixed，避免 TUN 干扰 Tailscale 路由），A 用 `after_inbounds`（追加到 base）。

## 部署

```bash
# 部署 A（网关）
uv run pyinfra inventory.py --limit mt3000-st -y deploy.py

# B 端生成配置后手动启动（或通过 systemd/sing-tools.timer）
uv run app.py generate camp-pk | sudo tee /etc/sing-box/config.json
sudo systemctl restart sing-box
```

## 验证

```bash
# 通过 relay 出站 → 应返回 A 的代理出口 IP
curl -x http://127.0.0.1:9999 http://httpbin.org/ip

# 直接出站（如果 B 的 route.final=relay-out，也会走 relay）
curl http://httpbin.org/ip
```

两个 IP 一致则 relay 正常工作。

## 关键点

1. **vless 而非 http**：sing-box 的 `http` outbound → `http` inbound 不能 chain——http outbound 不会重写请求为 proxy 格式，导致 A 收到 `GET /ip` 而非 `GET http://host/ip`。
2. **`bind_interface: tailscale0`**：sing-box 的 outbound transport connection 不走 route rules，必须在 outbound 上显式绑定 Tailscale 接口。
3. **B 端去 TUN**：TUN 的 fwmark 会使 `direct`/`tailscale0-out` 都不可达 Tailscale IP。B 作为纯 relay 客户端不应启用 TUN。
4. **`inbounds` vs `after_inbounds`**：host 模板中 `inbounds` 替换 base inbounds，`after_inbounds` 追加到 base 后面。
