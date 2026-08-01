#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this command as the normal VM user, not with sudo."
    exit 1
fi

config_file="/etc/opspilot-dashboard/integrations.env"

sudo -v

if ! sudo test -f "$config_file"; then
    echo "OpsPilot integration configuration was not found: $config_file"
    exit 1
fi

if sudo systemctl list-unit-files \
    opspilot-cpu-alert.timer \
    --no-legend 2>/dev/null | grep -q '^opspilot-cpu-alert.timer'; then
    sudo systemctl disable --now opspilot-cpu-alert.timer
else
    echo "Automatic CPU timer: not installed"
fi

sudo sed -i \
    's/^OPSPILOT_INTEGRATION_MODE=.*/OPSPILOT_INTEGRATION_MODE=draft/' \
    "$config_file"
sudo systemctl restart opspilot-dashboard-agent.service

echo "OpsPilot integration mode: DRAFT"
echo "Automatic CPU timer: disabled"
echo "External writes: disabled"
