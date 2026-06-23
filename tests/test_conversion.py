"""Tests for proxy URL -> sing-box config conversion in app.Outbound.

All credentials, hostnames, and identifiers are mock values.
"""

import pytest

from app import Outbound

# ── Shared mock values ──────────────────────────────────────────────────
_MOCK_UUID = "00000000-0000-0000-0000-000000000000"
_MOCK_UUID_2 = "11111111-1111-1111-1111-111111111111"
_MOCK_VMESS_UUID = "22222222-2222-2222-2222-222222222222"
_MOCK_SS_PASS = "test-pass"
_MOCK_SERVER = "example.com"
_MOCK_SNI = "sni.example.com"
_MOCK_REALITY_PBK = "mock-reality-public-key"
_MOCK_REALITY_SID = "abcdef01"
_MOCK_IP = "10.0.0.1"
_MOCK_IP_2 = "10.0.0.2"

# ── Shadowsocks ────────────────────────────────────────────────────────

def test_ss_base64():
    """SS with base64-encoded method:password (SIP002 standard)."""
    url = "ss://YWVzLTEyOC1nY206dGVzdC1wYXNz@example.com:443#test-ss-b64"
    ob = Outbound("p", url)
    assert ob.sing["type"] == "shadowsocks"
    assert ob.sing["server"] == "example.com"
    assert ob.sing["server_port"] == 443
    assert ob.sing["method"] == "aes-128-gcm"
    assert ob.sing["password"] == _MOCK_SS_PASS


def test_ss_url_encoded():
    """SS with URL-encoded plain method:password (SIP002 alternative form)."""
    url = "ss://aes-128-gcm%3Atest-pass@example.com:443#test-ss-plain"
    ob = Outbound("p", url)
    assert ob.sing["type"] == "shadowsocks"
    assert ob.sing["server"] == "example.com"
    assert ob.sing["server_port"] == 443
    assert ob.sing["method"] == "aes-128-gcm"
    assert ob.sing["password"] == _MOCK_SS_PASS


# ── VLESS standard TLS ─────────────────────────────────────────────────

def test_vless_tls_tcp():
    """VLESS over TLS/TCP with utls fingerprint."""
    url = (
        f"vless://{_MOCK_UUID}@{_MOCK_IP}:443"
        "?encryption=none&type=tcp&fp=firefox&flow=xtls-rprx-vision"
        f"&security=tls&sni={_MOCK_SNI}"
        "#VLESS-TLS"
    )
    ob = Outbound("p", url)
    assert ob.sing["type"] == "vless"
    assert ob.sing["server"] == _MOCK_IP
    assert ob.sing["server_port"] == 443
    assert ob.sing["uuid"] == _MOCK_UUID
    assert ob.sing["flow"] == "xtls-rprx-vision"
    assert ob.sing["network"] == "tcp"
    assert ob.sing["tls"]["enabled"] is True
    assert ob.sing["tls"]["server_name"] == _MOCK_SNI
    assert ob.sing["tls"]["utls"]["enabled"] is True
    assert ob.sing["tls"]["utls"]["fingerprint"] == "firefox"


def test_vless_tls_tcp_with_alpn():
    """VLESS TLS with alpn from URL query param."""
    url = (
        f"vless://{_MOCK_UUID}@{_MOCK_IP}:443"
        "?encryption=none&type=tcp&fp=firefox&flow=xtls-rprx-vision"
        f"&security=tls&sni={_MOCK_SNI}&alpn=h2%2Chttp%2F1.1"
        "#VLESS-ALPN"
    )
    ob = Outbound("p", url)
    assert ob.sing["tls"]["alpn"] == ["h2", "http/1.1"]


# ── VLESS Reality ──────────────────────────────────────────────────────

def test_vless_reality():
    """VLESS Reality must produce tls.reality with public_key and short_id."""
    url = (
        f"vless://{_MOCK_UUID}@{_MOCK_SERVER}:443"
        "?encryption=none&type=tcp&fp=firefox&flow=xtls-rprx-vision"
        f"&security=reality&sni={_MOCK_SNI}"
        f"&pbk={_MOCK_REALITY_PBK}"
        f"&sid={_MOCK_REALITY_SID}"
        "#VLESS-Reality"
    )
    ob = Outbound("p", url)
    assert ob.sing["type"] == "vless"
    assert ob.sing["tls"]["enabled"] is True
    reality = ob.sing["tls"]["reality"]
    assert reality["enabled"] is True
    assert reality["public_key"] == _MOCK_REALITY_PBK
    assert reality["short_id"] == _MOCK_REALITY_SID
    assert ob.sing["tls"]["utls"]["enabled"] is True
    assert ob.sing["tls"]["utls"]["fingerprint"] == "firefox"
    assert ob.sing["flow"] == "xtls-rprx-vision"


def test_vless_reality_with_alpn():
    """VLESS Reality with alpn."""
    url = (
        f"vless://{_MOCK_UUID}@{_MOCK_SERVER}:443"
        "?encryption=none&type=tcp&fp=firefox&flow=xtls-rprx-vision"
        f"&security=reality&sni={_MOCK_SNI}"
        f"&pbk={_MOCK_REALITY_PBK}&sid={_MOCK_REALITY_SID}"
        "&alpn=h2%2Chttp%2F1.1"
        "#VLESS-Reality-ALPN"
    )
    ob = Outbound("p", url)
    assert ob.sing["tls"]["alpn"] == ["h2", "http/1.1"]


# ── VLESS transport variants ───────────────────────────────────────────

def test_vless_grpc():
    """VLESS with gRPC transport."""
    url = (
        f"vless://{_MOCK_UUID}@test.example.net:443"
        "?encryption=none&type=grpc&fp=firefox&security=tls"
        "&sni=test.example.net&serviceName=my-grpc-svc"
        "#VLESS-gRPC"
    )
    ob = Outbound("p", url)
    assert ob.sing["transport"]["type"] == "grpc"
    assert ob.sing["transport"]["service_name"] == "my-grpc-svc"


def test_vless_ws():
    """VLESS with WebSocket transport and Host header."""
    url = (
        f"vless://{_MOCK_UUID}@test.example.net:443"
        "?encryption=none&type=ws&fp=firefox&security=tls"
        "&sni=test.example.net&host=ws-host.example.com&path=%2Fws-path"
        "#VLESS-WS"
    )
    ob = Outbound("p", url)
    assert ob.sing["transport"]["type"] == "ws"
    assert ob.sing["transport"]["path"] == "/ws-path"
    assert ob.sing["transport"]["headers"] == {"Host": "ws-host.example.com"}


def test_vless_xhttp_rejected():
    """VLESS xhttp/splithttp is unsupported by sing-box, must raise ValueError."""
    url = (
        f"vless://{_MOCK_UUID}@{_MOCK_IP_2}:443"
        "?encryption=none&type=xhttp&fp=firefox&security=tls"
        f"&sni={_MOCK_SNI}&host=xhttp-host.example.com&path=%2Ftest-path"
        "#VLESS-XHTTP"
    )
    with pytest.raises(ValueError, match="xhttp"):
        Outbound("p", url)


def test_vless_no_security_unless_reality_or_tls():
    """VLESS without TLS: code must conditionally disable TLS."""
    url = (
        f"vless://{_MOCK_UUID}@test.example.net:443"
        "?encryption=none&type=tcp&security=none"
        "#VLESS-noTLS"
    )
    ob = Outbound("p", url)
    assert ob.sing["tls"]["enabled"] is False


# ── Hysteria2 ──────────────────────────────────────────────────────────

def test_hysteria2_basic():
    """Basic hysteria2 outbound."""
    url = (
        f"hysteria2://{_MOCK_UUID}@test.example.net:443"
        f"?sni={_MOCK_SNI}&alpn=h3"
        "#HY2-basic"
    )
    ob = Outbound("p", url)
    assert ob.sing["type"] == "hysteria2"
    assert ob.sing["server"] == "test.example.net"
    assert ob.sing["server_port"] == 443
    assert ob.sing["password"] == _MOCK_UUID
    assert ob.sing["tls"]["enabled"] is True
    assert ob.sing["tls"]["server_name"] == _MOCK_SNI


def test_hysteria2_with_port_hop():
    """Hysteria2 with mport (port hopping) and hopinterval."""
    url = (
        f"hysteria2://{_MOCK_UUID}@test.example.net:443"
        f"?sni={_MOCK_SNI}&alpn=h3"
        "&mport=30000-32000&hopinterval=30s"
        "#HY2-hop"
    )
    ob = Outbound("p", url)
    assert ob.sing["hop_interval"] == "30s"
    assert ob.sing["server_ports"] == ["30000:32000"]


# ── Trojan ─────────────────────────────────────────────────────────────

def test_trojan():
    """Standard trojan outbound."""
    url = (
        "trojan://password123@trojan.example.com:443"
        "?peer=trojan.example.com&allowInsecure=0"
        "#Trojan"
    )
    ob = Outbound("p", url)
    assert ob.sing["type"] == "trojan"
    assert ob.sing["server"] == "trojan.example.com"
    assert ob.sing["server_port"] == 443
    assert ob.sing["password"] == "password123"
    assert ob.sing["tls"]["enabled"] is True
    assert ob.sing["tls"]["server_name"] == "trojan.example.com"
    assert ob.sing["tls"]["insecure"] is False


# ── AnyTLS ─────────────────────────────────────────────────────────────

def test_anytls():
    """AnyTLS outbound — tcp_fast_open must be stripped."""
    url = (
        f"anytls://{_MOCK_UUID_2}@anytls.example.com:44592"
        "?sni=example.net&insecure=1"
        "#AnyTLS"
    )
    ob = Outbound("p", url)
    assert ob.sing["type"] == "anytls"
    assert ob.sing["server"] == "anytls.example.com"
    assert ob.sing["server_port"] == 44592
    assert ob.sing["password"] == _MOCK_UUID_2
    assert ob.sing["tls"]["enabled"] is True
    assert ob.sing["tls"]["server_name"] == "example.net"
    assert ob.sing["tls"]["insecure"] is True
    assert "tcp_fast_open" not in ob.sing


# ── VMess ──────────────────────────────────────────────────────────────

def test_vmess_ws():
    """VMess with WebSocket transport."""
    vmess_json = (
        '{"v":"2","ps":"test-vmess-ws","add":"vmess.example.com","port":"443",'
        '"id":"22222222-2222-2222-2222-222222222222","aid":"0",'
        '"net":"ws","host":"ws-host.example.com","path":"/grpc-path","tls":""}'
    )
    import base64
    b64 = base64.urlsafe_b64encode(vmess_json.encode()).decode().rstrip("=")
    url = f"vmess://{b64}"
    ob = Outbound("p", url)
    assert ob.sing["type"] == "vmess"
    assert ob.sing["server"] == "vmess.example.com"
    assert ob.sing["server_port"] == 443
    assert ob.sing["uuid"] == _MOCK_VMESS_UUID
    assert ob.sing["alter_id"] == 0
    assert ob.sing["security"] == "auto"
    assert ob.sing["transport"]["type"] == "ws"
    assert ob.sing["transport"]["path"] == "/grpc-path"
    assert ob.sing["transport"]["headers"] == {"Host": "ws-host.example.com"}


# ── Edge cases ─────────────────────────────────────────────────────────

def test_vless_no_flow():
    """VLESS without flow should omit the flow field entirely."""
    url = (
        f"vless://{_MOCK_UUID}@test.example.net:443"
        "?encryption=none&type=tcp&fp=firefox&security=tls"
        f"&sni={_MOCK_SNI}"
        "#VLESS-noflow"
    )
    ob = Outbound("p", url)
    assert "flow" not in ob.sing


def test_vless_flow_empty():
    """VLESS with empty flow param should omit flow field."""
    url = (
        f"vless://{_MOCK_UUID}@test.example.net:443"
        "?encryption=none&type=tcp&fp=firefox&flow=&security=tls"
        f"&sni={_MOCK_SNI}"
        "#VLESS-emptyflow"
    )
    ob = Outbound("p", url)
    assert "flow" not in ob.sing


def test_invalid_scheme_raises():
    """Unknown scheme must raise ValueError."""
    with pytest.raises(ValueError):
        Outbound("p", "unknown://something")


def test_server_port_int():
    """server_port must be an integer, not string."""
    url = (
        f"vless://{_MOCK_UUID}@test.example.net:8080"
        "?encryption=none&type=tcp&security=tls&sni=example.com"
        "#test"
    )
    ob = Outbound("p", url)
    assert isinstance(ob.sing["server_port"], int)
    assert ob.sing["server_port"] == 8080
