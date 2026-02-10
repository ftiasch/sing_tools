import base64
import json
import logging
import os
import re
import subprocess
from typing import Annotated
from urllib.parse import parse_qs, unquote, urlparse

import paramiko
import typer
import yaml
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Precompile regex pattern for Japan variants
HK_PATTERN = re.compile(r"(HK|Hong Kong|��)", re.IGNORECASE)
JP_PATTERN = re.compile(r"(JP|japan|��|日本)", re.IGNORECASE)
RU_PATTERN = re.compile(r"(RU|russia|��🇺)", re.IGNORECASE)
US_PATTERN = re.compile(r"(US|United\w*States|🇺🇸)", re.IGNORECASE)


def parse_server_port(server_port: str) -> tuple[str, str]:
    """Parse server and port from server_port string, handling both IPv4 and IPv6 addresses."""
    # Handle IPv6 addresses (enclosed in brackets) and IPv4 addresses
    if server_port.startswith("[") and "]:" in server_port:
        # IPv6 address format: [IPv6]:port
        server_end = server_port.index("]:")
        server = server_port[1:server_end]
        port = server_port[server_end + 2 :]
    else:
        # IPv4 address format: server:port
        server, port = server_port.split(":", 1)
    return server, port


class ParamikoConfig(BaseModel):
    host: str


class ProviderConfig(BaseModel):
    url: str
    ua: str = ""
    paramiko: ParamikoConfig | None = None


class HostConfig(BaseModel):
    outbounds: list[str] = Field(default_factory=list)
    sudo: bool = False


class Config(BaseModel):
    db_path: str
    timeout: int
    github_proxy: str = ""
    providers: dict[str, ProviderConfig]
    hosts: dict[str, HostConfig]


class FileUtils:
    @staticmethod
    def _load_yaml_file(file_path):
        with open(file_path, "r") as f:
            return yaml.safe_load(f)

    @staticmethod
    def _load_db(config: Config):
        try:
            with open(config.db_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    @staticmethod
    def _save_db(config: Config, db):
        with open(config.db_path, "w") as f:
            json.dump(db, f)


def b64decode(b):
    return base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)).decode("utf-8")


def dict_merge(g, h):
    f = g.copy()
    for key, value in h.items():
        if key in f and isinstance(value, dict):
            f[key] = dict_merge(f[key], value)
        else:
            f[key] = value
    return f


SING_DIAL = {
    "reuse_addr": True,
    "tcp_fast_open": True,
    "tcp_multi_path": True,
    "udp_fragment": True,
}


class SimpleOutbound:
    """Simple outbound class for storing sing-box configurations as-is"""

    def __init__(self, provider: str, config: dict):
        self.provider = provider
        config = config.copy()  # Don't modify the original

        # Normalize server_port to be an integer (uint16 compatible)
        if "server_port" in config:
            try:
                server_port = config["server_port"]
                if isinstance(server_port, str):
                    config["server_port"] = int(server_port)
                elif isinstance(server_port, (int, float)):
                    config["server_port"] = int(server_port)
                # If it's already an int, leave it as is
            except (ValueError, TypeError):
                logging.warning(
                    f"Invalid server_port value: {config['server_port']}, keeping original"
                )

        self.config = config

    @property
    def name(self) -> str:
        """Get the name/tag from the config"""
        tag = self.config.get("tag", "")
        return f"[{self.provider}] {tag}" if tag else f"[{self.provider}] unnamed"

    def get_named_config(self, name: str, proxy_type: str) -> dict:
        """Get the configuration with a custom name and type (ducktyping compatible with Outbound)"""
        if proxy_type == "sing":
            config = self.config.copy()
            config["tag"] = name
            return config
        else:
            raise ValueError(f"Unsupported proxy type: {proxy_type}")


class Outbound:
    __provider: str
    __name: str
    sing: dict

    @property
    def name(self):
        return f"[{self.__provider}] {self.__name}"

    def __init__(self, provider, config):
        self.__provider = provider
        parsed_url = urlparse(config)
        match parsed_url.scheme:
            case "ss":
                # Format: ss://base64(method:password)@host:port#name
                netloc = parsed_url.netloc
                if "@" not in netloc:
                    raise ValueError("Invalid SS URL format")
                method_password, server_port = netloc.split("@", 1)
                decoded_method_password = b64decode(method_password)
                if ":" not in decoded_method_password:
                    raise ValueError("Invalid SS URL format")
                method, password = decoded_method_password.split(":", 1)
                server, port = parse_server_port(server_port)
                self.__name = unquote(parsed_url.fragment, encoding="utf-8")
                self.sing = {
                    **SING_DIAL,
                    "type": "shadowsocks",
                    "server": server,
                    "server_port": int(port),
                    "method": method,
                    "password": password,
                }
            case "ssr":
                parts = b64decode(parsed_url.netloc).split(":")
                if len(parts) != 6:
                    raise ValueError("Invalid SSR URL format")
                (
                    server,
                    port,
                    protocol,
                    method,
                    obfs,
                    rest,
                ) = parts
                parsed_rest = urlparse(rest)
                password = parsed_rest.path[:-1]  # Remove the trailing `/`
                remarks = parse_qs(parsed_rest.query).get("remarks", [""])[0]
                self.__name = b64decode(remarks)
                # SSR not supported in sing-box
                raise ValueError("SSR protocol is not supported")
            case "trojan":
                parts = parsed_url.netloc.split("@")
                if len(parts) != 2:
                    raise ValueError("Invalid Trojan URL format")
                password, server_port = parts
                server, port = parse_server_port(server_port)
                qs = parse_qs(parsed_url.query)
                sni = qs.get("peer", [""])[0]
                skip_cert_verify = qs.get("allowInsecure", [False])[0] == "1"
                self.__name = unquote(parsed_url.fragment, encoding="utf-8")
                self.sing = {
                    **SING_DIAL,
                    "type": "trojan",
                    "server": server,
                    "server_port": int(port),
                    "password": password,
                    "tls": {
                        "enabled": True,
                        "insecure": skip_cert_verify,
                        "server_name": sni,
                    },
                }
            case "vless":
                parts = parsed_url.netloc.split("@")
                if len(parts) != 2:
                    raise ValueError("Invalid VLESS URL format")
                uuid, server_port = parts
                server, port = parse_server_port(server_port)
                qs = parse_qs(parsed_url.query)
                security = qs.get("security", ["none"])[0]
                sni = qs.get("sni", [""])[0]
                flow = qs.get("flow", [""])[0]
                transport = qs.get("type", [""])[0]
                fp = qs.get("fp", [""])[0]
                self.__name = unquote(parsed_url.fragment, encoding="utf-8")
                self.sing = {
                    **SING_DIAL,
                    "type": "vless",
                    "server": server,
                    "server_port": int(port),
                    "tls": {
                        "enabled": True,
                        "server_name": sni,
                        "utls": {"enabled": True, "fingerprint": fp},
                    },
                    "uuid": uuid,
                    "flow": "xtls-rprx-vision",
                    "network": "tcp",
                }
                if transport == "grpc":
                    grpc_service_name = qs.get("serviceName", [""])[0]
                    self.sing["transport"] = {
                        "type": "grpc",
                        "service_name": grpc_service_name,
                    }
            case "vmess":
                # vmess://base64(JSON)
                # The JSON contains: v, ps, add, port, id, aid, net, type, host, path, tls
                try:
                    json_str = b64decode(parsed_url.netloc)
                    # Handle malformed JSON (missing closing quote for tls field)
                    if json_str.endswith('"tls":"}'):
                        json_str = json_str.replace('"tls":"}', '"tls":""}')
                    vmess_config = json.loads(json_str)
                except Exception:
                    raise ValueError("Invalid VMess URL format")

                server = vmess_config.get("add", "")
                port = vmess_config.get("port", "")
                uuid = vmess_config.get("id", "")
                alter_id = int(vmess_config.get("aid", "0"))
                net = vmess_config.get("net", "tcp")
                self.__name = vmess_config.get("ps", "")

                # Build sing-box config
                self.sing = {
                    **SING_DIAL,
                    "type": "vmess",
                    "server": server,
                    "server_port": int(port),
                    "uuid": uuid,
                    "alter_id": alter_id,
                    "security": "auto",
                    "network": "tcp",
                }

                # Handle websocket transport
                if net == "ws":
                    host = vmess_config.get("host", "")
                    path = vmess_config.get("path", "")
                    transport_config = {
                        "type": "ws",
                        "path": path,
                    }
                    if host:
                        transport_config["headers"] = {"Host": host}
                    self.sing["transport"] = transport_config
            case _:
                raise ValueError("Unknown scheme")

    def get_named_config(self, name, proxy_type):
        if proxy_type == "sing":
            config = self.sing.copy()
            config["tag"] = name
            return config
        else:
            raise ValueError(f"Unsupported proxy type: {proxy_type}")


class Subscription:
    @staticmethod
    def parse(name, data):
        # Try to parse as JSON first (sing-box configuration)
        try:
            config_data = json.loads(data)
            if isinstance(config_data, dict) and "outbounds" in config_data:
                logging.info("%s: Detected sing-box configuration", name)
                yield from Subscription._parse_singbox_config(name, config_data)
                return
        except (json.JSONDecodeError, KeyError):
            # Not a valid JSON or doesn't have outbounds, treat as traditional subscription
            pass

        # Handle as base64-encoded traditional subscription
        try:
            decoded_data = b64decode(data)
        except ValueError:
            logging.error("%s: Error decoding base64", name)
            return

        for config in decoded_data.splitlines():
            logging.info("%s: Parsing outbound %s...", name, config)
            try:
                yield Outbound(name, config)
            except Exception:
                logging.exception("%s: Error parsing %s", name, config)

    @staticmethod
    def _parse_singbox_config(name, config_data):
        """Parse sing-box configuration and filter outbounds"""
        outbounds = config_data.get("outbounds", [])

        # Filter out unwanted outbound types
        filtered_outbounds = []
        for outbound in outbounds:
            outbound_type = outbound.get("type", "").lower()
            tag = outbound.get("tag", "")

            # Skip unwanted outbound types
            if outbound_type in ["direct", "block", "dns", "selector", "urltest"]:
                logging.info(
                    "%s: Skipping %s outbound (type: %s)", name, tag, outbound_type
                )
                continue

            filtered_outbounds.append(outbound)

        logging.info(
            "%s: Found %d valid outbounds from sing-box config",
            name,
            len(filtered_outbounds),
        )

        # Create SimpleOutbound objects for each valid outbound
        for outbound in filtered_outbounds:
            try:
                yield SimpleOutbound(name, outbound)
            except Exception as e:
                logging.exception(
                    "%s: Error creating SimpleOutbound for %s: %s",
                    name,
                    outbound.get("tag", "unknown"),
                    e,
                )


app = typer.Typer()


@app.command()
def download(provider_selector: Annotated[str, typer.Argument()] = ".*"):
    config_dict = FileUtils._load_yaml_file("config.yaml")
    config = Config(**config_dict)
    print(config)
    db = FileUtils._load_db(config)
    if "providers" not in db:
        db["providers"] = {}
    provider_pattern = re.compile(provider_selector)

    ssh = None
    current_ssh_host = None

    try:
        for name, provider_config in config.providers.items():
            if not provider_pattern.match(name):
                continue
            logging.info("%s: Downloading...", name)

            # Build curl command
            curl_command = f"curl -4 -m {config.timeout}"
            if provider_config.ua:
                curl_command += f" -A '{provider_config.ua}'"
            curl_command += f" '{provider_config.url}'"

            # Check if provider has paramiko config
            if provider_config.paramiko:
                ssh_host = provider_config.paramiko.host
                # Reconnect only if host changed
                if ssh is None or current_ssh_host != ssh_host:
                    if ssh is not None:
                        ssh.close()
                    ssh = paramiko.SSHClient()
                    ssh.load_system_host_keys()
                    ssh.connect(ssh_host)
                    current_ssh_host = ssh_host
                _, stdout, _ = ssh.exec_command(curl_command)
                content = stdout.read().decode("utf-8")
            else:
                # Download locally
                result = subprocess.run(
                    curl_command, shell=True, capture_output=True, text=True
                )
                content = result.stdout

            if content:
                # Validate content by parsing it
                outbounds = list(Subscription.parse(name, content))
                if outbounds:
                    db["providers"][name] = content
                    logging.info("%s: Downloaded (%d outbounds)", name, len(outbounds))
                else:
                    logging.warning("%s: Downloaded content contains no valid outbounds, skipping", name)
            else:
                logging.error("%s: Failed to download", name)
    finally:
        if ssh is not None:
            ssh.close()
        FileUtils._save_db(config, db)


class ProxyGrouper:
    def __init__(self, proxies):
        self.groups = {}
        for proxy in proxies:
            name = proxy.get("name") or proxy.get(
                "tag"
            )  # `name` for mihomo, `tag` for sing
            if RU_PATTERN.search(name):
                continue
            self.__add("proxy-out", name)
            if HK_PATTERN.search(name):
                self.__add("hk-out", name)
            if JP_PATTERN.search(name):
                self.__add("jp-out", name)
            if US_PATTERN.search(name):
                self.__add("us-out", name)

    def __add(self, group, name):
        if group not in self.groups:
            self.groups[group] = []
        self.groups[group].append(name)


def _normalize_rule_set(maybe_rule_set: str | list[str] | None) -> list[str]:
    if maybe_rule_set is None:
        return []
    if isinstance(maybe_rule_set, str):
        return [maybe_rule_set]
    return maybe_rule_set


def _combine_rules(config):
    # concat before_rules && rules && after_rules
    config["rules"] = (
        config.get("before_rules", [])
        + config.get("rules", [])
        + config.get("after_rules", [])
    )
    if "before_rules" in config:
        del config["before_rules"]
    if "after_rules" in config:
        del config["after_rules"]


def _generate(host):
    logging.info("[sing_tools]")
    config_dict = FileUtils._load_yaml_file("config.yaml")
    config = Config(**config_dict)
    host_config = config.hosts[host]
    assert host_config is not None, f"Host '{host}' not found in config"
    db = FileUtils._load_db(config)
    outbounds = []
    for name in host_config.outbounds:
        content = db["providers"][name]
        logging.info("%s: Parsing proxies...", name)
        for o in Subscription.parse(name, content):
            # Handle both Outbound and SimpleOutbound types
            outbounds.append(o)

    names, proxies = {}, []
    for o in outbounds:
        n = o.name
        count = names[n] = names.get(n, 0) + 1
        if count > 1:
            n += "#" + str(count - 1)

        # Both Outbound and SimpleOutbound have get_named_config method (ducktyping)
        proxies.append(o.get_named_config(n, "sing"))

    proxy_groups = ProxyGrouper(proxies).groups
    github_proxy = config.github_proxy
    output = FileUtils._load_yaml_file("templates/base.yaml")
    output = dict_merge(
        output, FileUtils._load_yaml_file(os.path.join("templates", f"{host}.yaml"))
    )

    # add proxy_groups & proxies
    proxy_group_template = FileUtils._load_yaml_file("templates/proxy_group.yaml")
    for group_name, outbounds in proxy_groups.items():
        group_config = proxy_group_template.copy()
        group_config["tag"] = group_name
        group_config["outbounds"] = outbounds
        output["outbounds"].append(group_config)
    output["outbounds"].extend(proxies)

    _combine_rules(output["dns"])
    _combine_rules(output["route"])

    # postprocess: replace rules against invalid outbounds with reject
    valid_outbounds = {"direct"} | set(proxy_groups.keys())
    for rule in output["route"]["rules"]:
        outbound = rule.get("outbound", None)
        if outbound is not None and outbound not in valid_outbounds:
            rule["action"] = "reject"
            del rule["outbound"]

    # postprocess: rule sets
    rule_sets = set()
    for rules in (output["dns"]["rules"], output["route"]["rules"]):
        for rule in rules:
            for urs in _normalize_rule_set(rule.get("rule_set", None)):
                rule_sets.add(urs)
            for sub_rule in rule.get("rules", []):
                for urs in _normalize_rule_set(sub_rule.get("rule_set", None)):
                    rule_sets.add(urs)
    for rule_set in rule_sets:
        if rule_set.startswith("geoip"):
            url = f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{rule_set}.srs"
        else:
            url = f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{rule_set}.srs"
        output["route"]["rule_set"].append(
            {
                "download_detour": "direct",
                "format": "binary",
                "tag": rule_set,
                "type": "remote",
                "update_interval": "1d",
                "url": github_proxy + url,
            }
        )
    return json.dumps(output, ensure_ascii=False, indent=2)


@app.command()
def generate(host: str):
    print(_generate(host))


if __name__ == "__main__":
    app()
