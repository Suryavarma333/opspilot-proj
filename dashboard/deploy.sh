#!/usr/bin/env bash

# Universal OpsPilot v1.0 deployment entry point.
# Chooses a clean install or an in-place upgrade without accepting credentials.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "### OPSPILOT V1.0 DEPLOYMENT ROUTER"
date -u
echo

if systemctl list-unit-files opspilot-dashboard-agent.service --no-legend 2>/dev/null |
   grep -q '^opspilot-dashboard-agent\.service'
then
    echo "Existing dashboard agent detected."
    echo "Deployment path: in-place upgrade"
    exec "$script_dir/upgrade.sh"
fi

echo "No dashboard agent detected."
echo "Deployment path: clean visual dashboard install"
exec "$script_dir/install.sh"
