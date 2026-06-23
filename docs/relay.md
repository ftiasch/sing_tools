# Sing-Box Relay Chain

两机通过 Tailscale 组 relay chain：A（网关，挂代理）开 vless inbound，B（客户端）把流量通过 Tailscale 转发到 A。

## 架构

```
B (客户端, e.g. camp-pk)                    A (网关, e.g. mt3000-st)
┌──────────────────────┐                  ┌──────────────────────┐
│  TUN inbound         │                  │  TUN inbound          │
│       │              │                  │       │              │
│       ▼              │                  │       ▼              │
│  route rules ────────┼──→ relay-out ───Tailscale──→ relay-in ─┼──→ proxy-out → internet
│  (Tailscale bypass)  │   (vless,        │       (vless)       │
│                      │   bind:ts0)      │                      │
└──────────────────────┘                  └──────────────────────┘
```

## 协议选择

**vless**（无 TLS）。Tailscale 已提供 WireGuard 加密，relay 层不需要额外加密。

不要用 `http` inbound/outbound 做 chain——sing-box 的 `http` outbound 不会把请求重写成 proxy 格式发给下游 inbound，导致 `read http request: EOF`。

## 配置

### A（网关，e.g. mt3000-st）

`templates/mt3000-st.yaml`（追加到 base inbounds）：

```yaml
after_inbounds:
  - type: vless
    tag: relay-in
    listen: "100.116.175.64"   # A 的 Tailscale IP
    listen_port: 46375
    users:
      - uuid: "b56dbbfd-639e-4e50-af16-a26d70e68480"
```

### B（客户端，e.g. camp-pk）

`config.yaml`：

```yaml
camp-pk:
  <<: *base
  outbounds: []     # 不需要 provider——走 relay
  sudo: true
```

`templates/camp-pk.yaml`：

```yaml
# 不覆写 inbounds——保留 base 的 TUN + mixed
after_inbounds:
  - type: http
    tag: test-in
    listen: "127.0.0.1"
    listen_port: 9999
outbounds:
  - type: vless
    tag: relay-out
    server: "100.116.175.64"   # A 的 Tailscale IP
    server_port: 46375
    uuid: "b56dbbfd-639e-4e50-af16-a26d70e68480"
    bind_interface: tailscale0   # 关键：绕过 TUN 路由
dns:
  servers:
    - tag: dns_proxy
      type: tls
      server: 8.8.8.8
      detour: relay-out         # DNS 也走 relay
    - tag: dns_direct
      type: tls
      server: 223.5.5.5
    - tag: dns_tailscale
      type: udp
      server: 100.100.100.100
      detour: tailscale0-out
route:
  final: relay-out              # 所有流量默认走 relay
  rules:
    - ip_cidr:
        - 100.0.0.0/8           # Tailscale IP 段 bypass
      outbound: tailscale0-out
    - inbound: test-in
      outbound: relay-out
```

## 关键设计决策

### `bind_interface: tailscale0`

**必须加在 relay-out 上。** 原因：sing-box 的 outbound transport connection（连到下游 server 的 TCP 连接）不走 route rules。如果不显式绑 tailscale0，即便加了 `ip_cidr → tailscale0-out` 的路由规则也匹配不到。

`SO_BINDTODEVICE` 在 OS 层面绕过所有路由表，无论 TUN 是否启用都有效。

### Tailscale IP bypass（`100.0.0.0/8 → tailscale0-out`）

当 B 启用 TUN 时，**所有流量**被 TUN 捕获进入 sing-box 路由。SSH 到 A、Tailscale DERP 等连接也不例外。这条规则让 Tailscale 流量直通 tailscale0，避免被 `final: relay-out` 送入 vless 隧道（那会损坏非代理协议）。

### `outbounds: []`（B 不放 provider）

B 不直接挂代理，所有流量走 relay → A → A 的 proxy-out。这避免了 B 本地 urltest 测速无意义的问题。

### `dns_proxy → detour: relay-out`

B 的 DNS 也走 relay，确保解析出的 IP 与 A 的代理出口一致。

## 模板系统约定

`_generate` 处理 host 模板时：

| 键 | 语义 |
|---|---|
| `inbounds` | 替换 base inbounds |
| `after_inbounds` | 追加到 base inbounds 之后 |
| `outbounds` | 追加到 base outbounds 之后（proxy groups 之前） |
| `route.rules` | 前置到 base route rules 之前（最高优先级） |

## 验证流程

1. **A 部署**：`pyinfra inventory.py deploy.py --limit mt3000-st`
2. **B 生成并启动**：`uv run app.py generate camp-pk | sudo tee /etc/sing-box/config.json && sudo systemctl restart sing-box`
3. **正向测试**：`curl -x http://127.0.0.1:9999 http://httpbin.org/ip` → 应返回 A 的代理出口 IP
4. **TUN 测试**：`curl http://httpbin.org/ip` → 应返回相同 IP
5. **负向测试**：临时去掉 relay-out → 规则被 postprocess 转为 `reject` → curl 失败
6. **日志确认**：`journalctl -u sing-box -f` 看到 `outbound/vless[relay-out]: outbound connection`
