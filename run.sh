#!/bin/bash -x
set -o errexit
cd "$(dirname "${BASH_SOURCE[0]}")"
uv run app.py download
uv run pyinfra inventory.py -y deploy.py
