from io import StringIO

import pyinfra.facts.server
from pyinfra import host
from pyinfra.operations import files, server

import app

# Generate the configuration
config_content = app._generate(host.name)
if host.data.type == "mihomo":
    config_path = "/etc/mihomo/config.yaml"
elif host.data.type == "sing":
    config_path = "/etc/sing-box/config.json"
else:
    raise ValueError(f"Unsupported type: {host.data.type}")

# Write the generated configuration to /etc/mihomo/config.yaml
files.put(
    name="Write generated configuration to configuration file",
    src=StringIO(config_content),
    dest=config_path,
)

sudo = host.data.sudo
if host.data.type == "mihomo":
    if (
        host.get_fact(
            pyinfra.facts.server.LinuxDistribution,
        ).get("name", "")
        == "ImmortalWrt"
    ):
        # Upload the mihomo init script
        files.put(
            name="Upload mihomo init script",
            src="init.d/mihomo",
            dest="/etc/init.d/mihomo",
        )

        # Set the executable permission
        files.file(
            name="Set executable permission for mihomo init script",
            path="/etc/init.d/mihomo",
            mode="755",
        )
    server.service(service="mihomo", restarted=True, _sudo=sudo)
else:
    server.service(service="sing-box", restarted=True, _sudo=sudo)
