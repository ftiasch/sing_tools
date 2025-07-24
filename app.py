import base64
import json
import logging
import re
from typing import Annotated
from urllib.parse import parse_qs, unquote, urlparse

import paramiko
import typer
import yaml
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Precompile regex pattern for Japan variants
JP_PATTERN = re.compile(r"(JP|japan|🇯🇵|日本)", re.IGNORECASE)
RU_PATTERN = re.compile(r"(RU|russia|🇷🇺)", re.IGNORECASE)
US_PATTERN = re.compile(r"(US|United States|🇺🇸)", re.IGNORECASE)


class FileUtils:
    @staticmethod
    def _load_yaml_file(file_path):
        with open(file_path, "r") as f:
            return yaml.safe_load(f)

    @staticmethod
    def _load_db(config):
        try:
            with open(config["db-path"], "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    @staticmethod
    def _save_db(config, db):
        with open(config["db-path"], "w") as f:
            json.dump(db, f)


def b64decode(b):
    return base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)).decode("utf-8")


SING_DIAL = {
    "reuse_addr": True,
    "tcp_fast_open": True,
    "tcp_multi_path": True,
    "udp_fragment": True,
}


class Outbound:
    __provider: str
    __name: str
    mihomo: dict
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
                server, port = server_port.split(":")
                self.__name = unquote(parsed_url.fragment, encoding="utf-8")
                self.mihomo = {
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "method": method,
                    "password": password,
                }
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
                self.mihomo = {
                    "type": "ssr",
                    "server": server,
                    "port": int(port),
                    "protocol": protocol,
                    "method": method,
                    "obfs": obfs,
                    "password": password,
                }
                # FIXME: generate sing config
            case "trojan":
                parts = parsed_url.netloc.split("@")
                if len(parts) != 2:
                    raise ValueError("Invalid Trojan URL format")
                password, server_port = parts
                server, port = server_port.split(":")
                qs = parse_qs(parsed_url.query)
                sni = qs.get("peer", [""])[0]
                skip_cert_verify = qs.get("allowInsecure", [False])[0] == "1"
                self.__name = unquote(parsed_url.fragment, encoding="utf-8")
                self.mihomo = {
                    "type": "trojan",
                    "server": server,
                    "port": int(port),
                    "udp": True,
                    "password": password,
                    "sni": sni,
                    "skip-cert-verify": skip_cert_verify,
                }
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
                server, port = server_port.split(":")
                qs = parse_qs(parsed_url.query)
                security = qs.get("security", ["none"])[0]
                sni = qs.get("sni", [""])[0]
                flow = qs.get("flow", [""])[0]
                transport = qs.get("type", [""])[0]
                fp = qs.get("fp", [""])[0]
                self.__name = unquote(parsed_url.fragment, encoding="utf-8")
                self.mihomo = {
                    "type": "vless",
                    "server": server,
                    "port": int(port),
                    "udp": True,
                    "uuid": uuid,
                    "servername": sni,
                    "flow": flow,
                    "network": "tcp",
                    "client-fingerprint": fp,
                }
                if security == "tls":
                    self.mihomo["tls"] = True
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
                    self.mihomo["grpc-opts"] = {"grpc-service-name": grpc_service_name}
                    self.sing["transport"] = {
                        "type": "grpc",
                        "service_name": grpc_service_name,
                    }
            case _:
                raise ValueError("Unknown scheme")

    def get_named_config(self, name, proxy_type):
        if proxy_type == "mihomo":
            config = self.mihomo.copy()
            config["name"] = name
            return config
        elif proxy_type == "sing":
            config = self.sing.copy()
            config["tag"] = name
            return config
        else:
            raise ValueError(f"Unsupported proxy type: {proxy_type}")


class ShareLink:
    @staticmethod
    def parse(name, data):
        try:
            decoded_data = b64decode(data)
        except ValueError:
            logging.error("%s: Error decoding base64", name)
        for config in decoded_data.splitlines():
            try:
                yield Outbound(name, config)
            except Exception:
                logging.exception("%s: Error parsing %s", name, config)


app = typer.Typer()


@app.command()
def download(provider_selector: Annotated[str, typer.Argument()] = ".*"):
    config = FileUtils._load_yaml_file("config.yaml")
    db = FileUtils._load_db(config)
    if "providers" not in db:
        db["providers"] = {}
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.connect(config["paramiko"]["host"])
    provider_pattern = re.compile(provider_selector)
    try:
        for name, url in config["providers"].items():
            if not provider_pattern.match(name):
                continue
            logging.info("%s: Downloading...", name)
            _, stdout, _ = ssh.exec_command(f"curl -4 -m {config['timeout']} '{url}'")
            stdout = stdout.read().decode("utf-8")
            if stdout:
                db["providers"][name] = db["providers"].get(name, []) + [stdout]
                logging.info("%s: Downloaded", name)
            else:
                logging.error("%s: Failed to download", name)
    finally:
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
            if JP_PATTERN.search(name):
                self.__add("jp-out", name)
            if US_PATTERN.search(name):
                self.__add("us-out", name)

    def __add(self, group, name):
        if group not in self.groups:
            self.groups[group] = []
        self.groups[group].append(name)


def _generate(host):
    logging.info("[sing_tools]")
    config = FileUtils._load_yaml_file("config.yaml")
    host_config = config["hosts"][host]
    db = FileUtils._load_db(config)
    outbounds = []
    for name in host_config["outbounds"]:
        sing_config = db["providers"][name]
        logging.info("%s: Parsing proxies...", name)
        for o in ShareLink.parse(name, sing_config[-1]):
            if name == "ww" and o.mihomo["type"] == "ssr":
                continue
            outbounds.append(o)

    proxy_type = host_config["type"]
    if proxy_type not in ("mihomo", "sing"):
        raise ValueError(f"Unsupported proxy type: {proxy_type}")
    names, proxies = {}, []
    for o in outbounds:
        n = o.name
        count = names[n] = names.get(n, 0) + 1
        if count > 1:
            n += "#" + str(count - 1)
        proxies.append(o.get_named_config(n, proxy_type))
    proxy_groups = ProxyGrouper(proxies).groups
    env = Environment(loader=FileSystemLoader("templates"))
    env.filters.update({"toyaml": lambda d: yaml.dump(d, allow_unicode=True).strip()})
    github_proxy = config.get("github-proxy", "")
    yaml_str = env.get_template(f"{host}.yaml").render(
        github_proxy=github_proxy,
        proxies=proxies,
        proxy_groups=proxy_groups,
    )
    match proxy_type:
        case "mihomo":
            return yaml_str
        case "sing":
            # sing post process
            sing_config = yaml.safe_load(yaml_str)
            # remove rules against invalid outbounds
            sing_config["route"]["rules"] = [
                rule
                for rule in sing_config["route"]["rules"]
                if rule.get("outbound", None) is None
                or rule["outbound"] == "direct"
                or rule["outbound"] in proxy_groups
            ]
            # add rule sets
            rule_sets = set()
            for rules in (sing_config["dns"]["rules"], sing_config["route"]["rules"]):
                for rule in rules:
                    used_rule_set = rule.get("rule_set", None)
                    if used_rule_set is not None:
                        if isinstance(used_rule_set, str):
                            rule_sets.add(used_rule_set)
                        else:
                            for urs in used_rule_set:
                                rule_sets.add(urs)
            for rule_set in rule_sets:
                if rule_set.startswith("geoip"):
                    url = f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{rule_set}.srs"
                else:
                    url = f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{rule_set}.srs"
                sing_config["route"]["rule_set"].append(
                    {
                        "download_detour": "direct",
                        "format": "binary",
                        "tag": rule_set,
                        "type": "remote",
                        "update_interval": "1d",
                        "url": github_proxy + url,
                    }
                )
                pass
            return json.dumps(sing_config, ensure_ascii=False, indent=2)


@app.command()
def generate(host: str):
    print(_generate(host))


if __name__ == "__main__":
    app()
