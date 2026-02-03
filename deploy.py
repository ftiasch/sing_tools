from io import StringIO

import pyinfra.facts.server
from pyinfra import host
from pyinfra.operations import files, server

import app

# Generate the configuration
config_content = app._generate(host.name)
config_path = "/etc/sing-box/config.json"

# Write the generated configuration to configuration file
files.put(
    name="Write generated configuration to configuration file",
    src=StringIO(config_content),
    dest=config_path,
)

server.service(service="sing-box", restarted=True, _sudo=host.data.sudo)
