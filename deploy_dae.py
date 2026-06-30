"""Deploy dae transparent proxy to camp-bb."""

import atexit
import shutil
import tempfile
import urllib.request
from pathlib import Path

from pyinfra.operations import files, pacman, server

GEOIP_URL = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
GEOSITE_URL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

GEO_DIR = "/usr/local/share/dae"
CONFIG_DIR = "/etc/dae"
LOCAL_CONFIG = Path(__file__).parent / "dae_config.dae"

# Temp dir that lives until the process exits (pyinfra runs ops after our code returns)
_tmpdir = tempfile.mkdtemp(prefix="dae_deploy_")
atexit.register(shutil.rmtree, _tmpdir, ignore_errors=True)

def _download_and_put(url: str, remote_path: str) -> None:
    """Download a file locally, then put it to the remote host."""
    local = Path(_tmpdir) / Path(remote_path).name
    print(f"Downloading {url} ...")
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    local.write_bytes(data)
    print(f"  -> {len(data)} bytes -> {local}")
    files.put(name=f"Put {remote_path}", src=str(local), dest=remote_path, _sudo=True)


# 1. Install dae-git
pacman.packages(
    name="Install dae-git",
    packages=["dae-git"],
    update=True,
    _sudo=True,
)

# 2. Ensure directories
files.directory(name="Ensure geo dir", path=GEO_DIR, _sudo=True)

# 3. Download and put geo data files
_download_and_put(GEOIP_URL, f"{GEO_DIR}/geoip.dat")
_download_and_put(GEOSITE_URL, f"{GEO_DIR}/geosite.dat")

# 4. Put dae config
files.put(
    name="Put dae config",
    src=str(LOCAL_CONFIG),
    dest=f"{CONFIG_DIR}/config.dae",
    _sudo=True,
)
files.file(
    name="Set config permissions",
    path=f"{CONFIG_DIR}/config.dae",
    mode="600",
    _sudo=True,
)

# 5. Enable and start dae
server.service(
    name="Enable and start dae",
    service="dae",
    enabled=True,
    running=True,
    _sudo=True,
)

# 6. Reload dae to pick up new config
server.service(
    name="Reload dae config",
    service="dae",
    reloaded=True,
    _sudo=True,
)

