#!/bin/bash
set -o errexit
mkdir -p ~/.config/systemd/user
# cp sing-tools.{service,timer} ~/.config/systemd/user/
# systemctl edit --user --full sing-tools.service
systemctl daemon-reload --user
