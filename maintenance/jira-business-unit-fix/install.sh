#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this installer as the normal VM user, not with sudo."
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
config_file="/etc/opspilot-dashboard/integrations.env"
backend_file="/opt/opspilot-dashboard/opspilot_dashboard_agent.py"
timestamp="$(date -u +%F-%H%M%S)"
backup_dir="/var/backups/opspilot-dashboard/business-unit-fix-$timestamp"
backup_config="$backup_dir/integrations.env.before"
backup_backend="$backup_dir/opspilot_dashboard_agent.py.before"
changes_started=0
completed=0

for command_name in curl python3 sha256sum sudo systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Required command is missing: $command_name"
        exit 1
    }
done

cd "$script_dir"
sha256sum --check --quiet CHECKSUMS.sha256
python3 -m py_compile files/business_unit_fix.py
sudo -v

if ! sudo test -f "$config_file"; then
    echo "OpsPilot integration configuration was not found: $config_file"
    exit 1
fi
if ! sudo test -f "$backend_file"; then
    echo "OpsPilot v0.9 backend was not found: $backend_file"
    exit 1
fi

rollback() {
    status=$?
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$changes_started" -eq 1 ] && [ "$completed" -eq 0 ]; then
        echo
        echo "Installation failed; restoring the previous OpsPilot backend and configuration."
        sudo install --preserve-timestamps -o root -g root -m 0600 \
            "$backup_config" "$config_file" || true
        sudo install --preserve-timestamps -o root -g root -m 0755 \
            "$backup_backend" "$backend_file" || true
        sudo systemctl restart opspilot-dashboard-agent.service || true
        echo "Automatic CPU timer remains disabled for safety."
        echo "Rollback evidence: $backup_dir"
    fi
    exit "$status"
}
trap rollback EXIT

# Stop retries first. The mode is then forced to draft before any backend edit.
if sudo systemctl list-unit-files opspilot-cpu-alert.timer --no-legend 2>/dev/null |
    grep -q '^opspilot-cpu-alert.timer'; then
    sudo systemctl disable --now opspilot-cpu-alert.timer
fi

sudo install -d -o root -g root -m 0700 "$backup_dir"
sudo cp --preserve=mode,ownership,timestamps "$config_file" "$backup_config"
sudo cp --preserve=mode,ownership,timestamps "$backend_file" "$backup_backend"
changes_started=1

sudo python3 - "$config_file" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
prefix = "OPSPILOT_INTEGRATION_MODE="
updated = []
found = False
for line in lines:
    if line.startswith(prefix):
        if not found:
            updated.append(prefix + "draft")
            found = True
    else:
        updated.append(line)
if not found:
    updated.append(prefix + "draft")
descriptor, temporary_name = tempfile.mkstemp(prefix=".integrations.", dir=path.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(updated) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_name, 0o600)
    os.chown(temporary_name, 0, 0)
    os.replace(temporary_name, path)
finally:
    try:
        os.unlink(temporary_name)
    except FileNotFoundError:
        pass
PY

sudo systemctl restart opspilot-dashboard-agent.service
sudo python3 files/business_unit_fix.py \
    --config "$config_file" \
    --backend "$backend_file"
sudo systemctl restart opspilot-dashboard-agent.service

ready=0
for _attempt in $(seq 1 20); do
    if curl --fail --silent --max-time 3 \
        http://127.0.0.1:3100/healthz >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    sudo systemctl status opspilot-dashboard-agent.service --no-pager || true
    sudo journalctl -u opspilot-dashboard-agent.service -n 30 --no-pager || true
    echo "OpsPilot backend did not become healthy."
    exit 1
fi

status_json="$(curl --fail --silent --show-error --max-time 10 \
    http://127.0.0.1:3100/api/v1/integrations/status)"
python3 - "$status_json" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
if data.get("mode") != "draft" or data.get("external_writes_enabled") is not False:
    raise SystemExit("Safety check failed: OpsPilot is not in draft mode")
PY

completed=1
echo
echo "OpsPilot Jira Business Unit fix: INSTALLED"
echo "Integration mode: DRAFT"
echo "Automatic CPU timer: disabled"
echo "External writes performed: false"
echo "Backend health: READY"
echo "Backup: $backup_dir"
echo "Next step: enable one controlled live test from automation/cpu-alert."
