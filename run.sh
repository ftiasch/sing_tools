#!/bin/bash -x
set -o errexit
cd "$(dirname "${BASH_SOURCE[0]}")"
uv run pyinfra inventory.py -y upload.py
