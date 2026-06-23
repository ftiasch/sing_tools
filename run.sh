#!/bin/bash -x
set -o errexit
cd "$(dirname "${BASH_SOURCE[0]}")"
uv run app.py download
uv run pyinfra inventory.py -y deploy.py
if [[ -n "$HEALTHCHECKS_URL" ]]; then
  curl -m 10 --retry 5 $HEALTHCHECKS_URL
fi
