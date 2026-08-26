from io import StringIO

from pyinfra import host
from pyinfra.operations import files, server

import app

# Server-only hosts (e.g. camp-bwh) have no outbounds: skip client deploy,
# otherwise the generated client config would overwrite the server config.
if not host.data.get("outbounds"):
    host.noop("no outbounds defined; skipping client deployment")
else:
    # Generate the configuration
    config_content = app._generate(host.name)
    config_path = "/etc/sing-box/config.json"

    # Write the generated configuration to configuration file
    files.put(
        name="Write generated configuration to configuration file",
        src=StringIO(config_content),
        dest=config_path,
        _sudo=host.data.sudo,
    )

    # Restart sing-box service
    # Note: On OpenWrt/ImmortalWrt, the service must be enabled via UCI to start
    server.service(
        service="sing-box",
        restarted=True,
        _sudo=host.data.sudo,
    )
