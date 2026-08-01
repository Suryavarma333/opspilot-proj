#!/usr/bin/env bash

# Install automatic shift-based roster selection for OpsPilot v0.9.0.

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this installer as the normal VM user, not with sudo."
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
files_dir="$script_dir/files"
config_dir="/etc/opspilot-dashboard"
config_file="$config_dir/integrations.env"
schedule_file="$config_dir/roster-schedule.csv"
roster_file="/var/lib/opspilot-dashboard-agent/current-oncall.csv"
program_file="/usr/local/libexec/opspilot-roster-rotation"
service_file="/etc/systemd/system/opspilot-roster-rotation.service"
timer_file="/etc/systemd/system/opspilot-roster-rotation.timer"
marker_file="$config_dir/.roster-rotation-v1-installed"
validation_file="$(mktemp)"
trap 'rm -f "$validation_file"' EXIT

for command_name in sha256sum python3 curl systemctl sudo; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required command is missing: $command_name"
        exit 1
    fi
done

cd "$script_dir"
sha256sum --check --quiet CHECKSUMS.sha256

if [ ! -f "$config_file" ]; then
    echo "OpsPilot integration configuration was not found: $config_file"
    exit 1
fi

if ! systemctl list-unit-files opspilot-dashboard-agent.service \
    --no-legend 2>/dev/null | grep -q '^opspilot-dashboard-agent.service'; then
    echo "OpsPilot dashboard agent is not installed."
    exit 1
fi

if ! getent group opspilot >/dev/null; then
    echo "Required system group does not exist: opspilot"
    exit 1
fi

sudo -v

sudo python3 - "$config_file" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
mode = ""
for line in path.read_text(encoding="utf-8").splitlines():
    if line.startswith("OPSPILOT_INTEGRATION_MODE="):
        mode = line.split("=", 1)[1].strip().lower()
        break
if mode != "draft":
    raise SystemExit(
        "Safety stop: OPSPILOT_INTEGRATION_MODE must be exactly draft"
    )
PY

sudo install -d -o root -g root -m 0750 "$config_dir"
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -d -o opspilot -g opspilot -m 0750 \
    /var/lib/opspilot-dashboard-agent

sudo install -o root -g root -m 0755 \
    "$files_dir/opspilot-roster-rotation.py" "$program_file"
sudo install -o root -g opspilot -m 0640 \
    "$files_dir/roster-schedule.csv" "$schedule_file"
sudo install -o root -g root -m 0644 \
    "$files_dir/opspilot-roster-rotation.service" "$service_file"
sudo install -o root -g root -m 0644 \
    "$files_dir/opspilot-roster-rotation.timer" "$timer_file"

rotate_token="yes"
if sudo test -e "$marker_file"; then
    rotate_token="no"
fi

sudo python3 - "$config_file" "$roster_file" "$rotate_token" <<'PY'
import os
import secrets
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
roster_path = sys.argv[2]
rotate_token = sys.argv[3] == "yes"
lines = path.read_text(encoding="utf-8").splitlines()


def set_key(key: str, value: str) -> None:
    global lines
    prefix = key + "="
    replacement = prefix + value
    found = False
    updated = []
    for line in lines:
        if line.startswith(prefix):
            if not found:
                updated.append(replacement)
                found = True
            continue
        updated.append(line)
    if not found:
        updated.append(replacement)
    lines = updated


set_key("OPSPILOT_INTEGRATION_MODE", "draft")
set_key("OPSPILOT_JIRA_ISSUE_TYPE", "INCIDENT")
set_key("OPSPILOT_ROSTER_CSV_PATH", roster_path)
if rotate_token:
    set_key("OPSPILOT_ACTION_TOKEN", secrets.token_urlsafe(32))

temporary_fd, temporary_name = tempfile.mkstemp(
    prefix=".integrations.env.", dir=path.parent
)
try:
    with os.fdopen(temporary_fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
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

sudo systemctl daemon-reload
sudo systemctl start opspilot-roster-rotation.service
sudo systemctl enable --now opspilot-roster-rotation.timer
sudo systemctl restart opspilot-dashboard-agent.service

backend_ready="no"
for _attempt in $(seq 1 20); do
    if curl --fail --silent --show-error --max-time 3 \
        http://127.0.0.1:3100/healthz >/dev/null 2>&1; then
        backend_ready="yes"
        break
    fi
    sleep 1
done

if [ "$backend_ready" != "yes" ]; then
    echo "OpsPilot backend did not become ready within 20 seconds."
    sudo systemctl status opspilot-dashboard-agent.service --no-pager -l || true
    exit 1
fi

http_status="$(curl --silent --show-error --max-time 30 \
    --output "$validation_file" \
    --write-out '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data '{}' \
    http://127.0.0.1:3100/api/v1/integrations/validate)"

python3 - "$validation_file" "$http_status" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
http_status = sys.argv[2]
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"Integration validation did not return valid JSON: {error}")

roster = data.get("checks", {}).get("roster", {})
if http_status != "200" or data.get("status") != "ready":
    print(json.dumps(data, indent=2))
    raise SystemExit(
        f"Read-only integration validation was not ready (HTTP {http_status})"
    )
if data.get("external_write_performed") is not False:
    raise SystemExit("Safety check failed: validation reported an external write")
if roster.get("status") != "resolved":
    raise SystemExit("Roster was not resolved by the dashboard agent")

print("OpsPilot shift rotation: PASS")
print("Current primary engineer:", roster.get("name", ""))
print("Jira validation:", data["checks"]["jira"].get("status", "unknown"))
print("External writes performed: false")
PY

sudo install -o root -g root -m 0600 /dev/null "$marker_file"

if [ "$rotate_token" = "yes" ]; then
    echo "Previously exposed action token: ROTATED (replacement not displayed)"
fi
echo "Integration mode: DRAFT"
echo "Timer state: $(systemctl is-active opspilot-roster-rotation.timer)"
echo "Next timer run:"
systemctl list-timers opspilot-roster-rotation.timer --no-pager
