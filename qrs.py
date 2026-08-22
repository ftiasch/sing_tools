import gzip
import struct
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

PROFILE_NAME = b"sing-tools"


def _uvarint(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _profile(config: str) -> bytes:
    config_bytes = config.encode()
    body = (
        _uvarint(len(PROFILE_NAME))
        + PROFILE_NAME
        + struct.pack(">i", 0)
        + _uvarint(len(config_bytes))
        + config_bytes
    )
    return b"\x03\x01" + gzip.compress(body, mtime=0)


if __name__ == "__main__":
    with TemporaryDirectory() as directory:
        profile = Path(directory, "sing-tools.bpf")
        profile.write_bytes(_profile(sys.stdin.read()))
        try:
            subprocess.run(
                [
                    "npx",
                    "--yes",
                    "--registry=https://registry.npmjs.org",
                    "qifi@0.1.0",
                    profile,
                ],
                check=True,
            )
        except KeyboardInterrupt:
            pass
