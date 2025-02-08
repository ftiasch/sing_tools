import base64
import json
import logging
from urllib.parse import parse_qs, unquote, urlparse

import paramiko
import typer
import yaml
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


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


class Outbound:
    __provider: str
    __name: str
    mihomo: dict

    @property
    def name(self):
        return f"[{self.__provider}] {self.__name}"

    def __init__(self, provider, config):
        self.__provider = provider
        parsed_url = urlparse(config)
        match parsed_url.scheme:
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
                    "network": transport,
                    "client-fingerprint": fp,
                }
                if security == "tls":
                    self.mihomo["tls"] = True
                if transport == "grpc":
                    self.mihomo["grpc-opts"] = {
                        "grpc-service-name": qs.get("serviceName", [""])[0]
                    }
            case _:
                raise ValueError("Unknown scheme")


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
def download():
    config = FileUtils._load_yaml_file("config.yaml")
    db = FileUtils._load_db(config)
    if "providers" not in db:
        db["providers"] = {}
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.connect(config["paramiko"]["host"])
    try:
        for name, url in config["providers"].items():
            _, stdout, _ = ssh.exec_command(f"curl -m {config['timeout']} '{url}'")
            stdout = stdout.read().decode("utf-8")
            if stdout:
                db["providers"][name] = db["providers"].get(name, []) + [stdout]
                logging.info("%s: Downloaded", name)
            else:
                logging.error("%s: Failed to download", name)
    finally:
        ssh.close()
        FileUtils._save_db(config, db)


def _generate(host: str):
    logging.info("[sing_tools]")
    config = FileUtils._load_yaml_file("config.yaml")
    host_config = config["hosts"][host]
    db = FileUtils._load_db(config)
    outbounds = []
    for name in host_config["outbounds"]:
        data = db["providers"][name]
        logging.info("%s: Parsing proxies...", name)
        for o in ShareLink.parse(name, data[-1]):
            if name == "ww" and o.mihomo["type"] == "ssr":
                continue
            outbounds.append(o)

    names, proxies = {}, []
    for o in outbounds:
        n = o.name
        count = names[n] = names.get(n, 0) + 1
        if count > 1:
            n += "#" + str(count - 1)
        m = o.mihomo.copy()
        m["name"] = n
        proxies.append(m)
    env = Environment(loader=FileSystemLoader("templates"))
    env.filters.update({"toyaml": lambda d: yaml.dump(d, allow_unicode=True).strip()})
    return env.get_template(f"{host}.yaml").render(
        github_proxy=config.get("github-proxy", ""),
        proxies=proxies,
    )


@app.command()
def generate(host: str):
    print(_generate(host))


if __name__ == "__main__":
    app()
