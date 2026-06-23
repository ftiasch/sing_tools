# IPv6 旁路由

camp-bb (10.11.1.2) 作为旁路由，通过 Linksys 上游获取 IPv6 前缀，sing-box 劫持 DNS 做 v6 分流。

## 架构

```
LAN 客户端                          camp-bb (旁路由)              Linksys (主路由)
─────────                          ──────────────               ───────────────
                                   ┌────────────────┐          ┌──────────────┐
  SLAAC: 2408:8206:...             │ dnsmasq ──────────────────│ DHCPv6-PD     │
  (从 Linksys 拿地址)              │  ├─ RA (high pri)  ──→    │ /60 prefix    │
                                   │  ├─ RDNSS:        │       │              │
  DNS: ──→ 2400:3200::1 ──────────│      2400:3200::1 │       │              │
                                   │  └─ DHCPv4        │       │              │
                                   │                   │       │              │
                                   │ sing-box          │       │              │
                                   │  ├─ TUN (fd00::)  │       │              │
                                   │  ├─ hijack-dns    │       │              │
                                   │  │  └─ 2400:3200::1      │              │
                                   │  ├─ DNS routing   │       │              │
                                   │  │  ├─ CN → direct (223.5.5.5 DoT)       │
                                   │  │  └─ !CN → proxy (8.8.8.8 DoT)        │
                                   │  └─ route rules    │       │              │
                                   │     └─ final: proxy-out   │              │
                                   └────────────────┘          └──────────────┘
```

## 关键设计决策

### DNS 劫持入口：`2400:3200::1`

和 v4 的 `223.5.5.5` 策略一致——这是一个真实的公网 DNS（AliDNS），不劫持也能用。sing-box 在 TUN 层劫持发往 `2400:3200::1:53` 的流量，按 geosite 规则分流：

- 国内域名 → dns_direct（DoT to `223.5.5.5`）
- 国外域名 → dns_proxy（DoT to `8.8.8.8`，走代理）

### RA：dnsmasq 发 high-priority Router Advertisement

Linksys 原本发 RA（medium priority）作为 v6 默认路由器。dnsmasq 扩展后以 **high priority** 发 RA，客户端会优先选 camp-bb 作为默认路由器：

```
enable-ra
dhcp-range=::,constructor:eno1,ra-only,12h
ra-param=eno1,high,30,1800
```

- `constructor:eno1` — 自动跟随 ISP 前缀变化（动态前缀）
- `ra-only` — SLAAC 模式，不分配 DHCPv6 地址
- `ra-param high` — 优先于 Linksys 的 medium
- RDNSS — 自动从 `dhcp-option=option6:dns-server,[2400:3200::1]` 生成

### 未做全流量透明代理

NDP proxy 未配置（`proxy_ndp=0`），全流量透明代理的回程路由不对称会导致 TCP 中断。当前和 v4 的设计一致：**只劫持 DNS，数据流量不强制走 sing-box**。

## 依赖

| 组件 | 配置 | 作用 |
|---|---|---|
| NetworkManager | eno1 `ipv6.method=auto` | 从 Linksys 获取 SLAAC 地址和默认路由 |
| Linksys | DHCPv6-PD `/60` | 提供上游 IPv6 前缀 |
| sysctl | `forwarding=1`, `accept_ra=2` | 允许转发 + 转发时仍接受 RA |
| dnsmasq | `enable-ra` + constructor | 发送 high-priority RA |
| sing-box | `strategy: prefer_ipv4` | DNS 双栈但优先 v4 |

## 配置文件变更

### /etc/dnsmasq.conf（新增 3 行）

```
enable-ra
dhcp-range=::,constructor:eno1,ra-only,12h
ra-param=eno1,high,30,1800
```

### /etc/sysctl.d/99-ipv6-forwarding.conf（新建）

```
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.eno1.forwarding = 1
net.ipv6.conf.eno1.accept_ra = 2
net.ipv6.conf.all.accept_ra = 2
```

### templates/base.yaml（2 处变更）

```yaml
dns:
  strategy: prefer_ipv4        # 原: ipv4_only
  …
route:
  default_domain_resolver:
    strategy: prefer_ipv4      # 原: ipv4_only
```

## 故障排查

### 前缀变了（ISP 重拨号）

dnsmasq 的 `constructor:eno1` 会自动跟上。如果客户端拿不到新前缀地址：

```bash
# 确认 dnsmasq RA 用新前缀
sudo journalctl -u dnsmasq --no-pager | grep "router advertisement on"

# 如果不是，重启 dnsmasq
sudo systemctl restart dnsmasq
```

### IPv6 默认路由消失

forwarding=1 会阻止接收 RA。确认：

```bash
sudo sysctl net.ipv6.conf.all.accept_ra=2
sudo sysctl net.ipv6.conf.eno1.accept_ra=2
```

### sing-box DNS 劫持不工作

```bash
# 测试 DNS 劫持
dig +short AAAA google.com @2400:3200::1   # 应返回 v6 地址
dig +short A baidu.com @2400:3200::1       # 应返回 v4 地址
```

### 客户端 DNS 配置

客户端应该通过 RA 的 RDNSS 自动获得 `2400:3200::1` 作为 DNS。如果客户端没收到 RA：

```bash
# 确认 RA 在广播
sudo python3 -c "
import socket, struct, time
sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.bind(('::', 0)); sock.settimeout(10)
while time.time() < 8:
    data, addr = sock.recvfrom(4096)
    if data[0] == 134:
        flags = data[5]; prf = (flags>>3)&3
        print(f'RA from {addr} prf={\"med/high/low\"[prf]}')
" 2>&1 | head -10
```

应看到 **两** 个 RA 源：Linksys (prf=medium) 和 camp-bb (prf=high)。

---
## 2026-06-19: IPv6 已禁用

主路由 disable IPv6 后，旁路由同步关闭 IPv6 功能，LAN 变为纯 IPv4。

### 变更清单

**dnsmasq** (`/etc/dnsmasq.conf`) — 删除 4 行：
- `enable-ra`
- `dhcp-range=::,constructor:eno1,ra-only,12h`
- `ra-param=eno1,high,30,1800`
- `dhcp-option=option6:dns-server,[2400:3200::1]`

**sing-box 模板** (`templates/base.yaml`) — 删除 3 处 IPv6 地址：
- TUN inbound: 移除 `fd00::1/126`（保留 `172.16.0.1/30`）
- DNS hijack: 移除 `2400:3200::1`（保留 `223.5.5.5`）
- DNS hijack: 移除 `fd00::2/128`（保留 `172.16.0.2/32`）

**保留**：
- 内核级 IPv6（`sysctl forwarding=1`, `accept_ra=2`）— tailscale/cilium 需要
- `listen: '::'` 在各 inbound — 同时监听 v4/v6 不影响
- `fd7a:115c:a1e0::/48` → tailscale0-out 路由规则

### 恢复

如需重新启用 IPv6，git revert 本提交即可。
