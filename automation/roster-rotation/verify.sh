#!/usr/bin/env bash

# Read-only verification for the OpsPilot roster rotation add-on.

set -euo pipefail

echo "Configured schedule:"
sudo sed -n '1,4p' /etc/opspilot-dashboard/roster-schedule.csv

echo
echo "Current generated roster:"
sudo sed -n '1,2p' \
    /var/lib/opspilot-dashboard-agent/current-oncall.csv

echo
echo "Automation state:"
systemctl is-enabled opspilot-roster-rotation.timer
systemctl is-active opspilot-roster-rotation.timer
systemctl list-timers opspilot-roster-rotation.timer --no-pager

echo
echo "Recent automation logs:"
sudo journalctl -u opspilot-roster-rotation.service -n 10 --no-pager

echo
echo "Read-only OpsPilot validation:"
curl --fail-with-body --silent --show-error --max-time 30 \
    -H 'Content-Type: application/json' \
    --data '{}' \
    http://127.0.0.1:3100/api/v1/integrations/validate \
    | python3 -m json.tool
