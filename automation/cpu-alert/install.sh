#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this installer as the normal VM user, not with sudo."
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
files_dir="$script_dir/files"
config_file="/etc/opspilot-dashboard/integrations.env"
validation_file="$(mktemp)"
trap 'rm -f "$validation_file"' EXIT

for command_name in curl python3 sha256sum sudo systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Required command is missing: $command_name"
        exit 1
    }
done

cd "$script_dir"
sha256sum --check --quiet CHECKSUMS.sha256
python3 -m py_compile files/opspilot_cpu_alert.py

sudo -v

# integrations.env is intentionally root-only. A normal-user `test -f` cannot
# traverse /etc/opspilot-dashboard and incorrectly reports that the file is
# missing, so all checks of this file must run through sudo.
if ! sudo test -f "$config_file"; then
    echo "OpsPilot integration configuration was not found: $config_file"
    exit 1
fi

if ! systemctl list-unit-files opspilot-dashboard-agent.service \
    --no-legend 2>/dev/null | grep -q '^opspilot-dashboard-agent.service'; then
    echo "OpsPilot v0.9 dashboard agent is not installed."
    exit 1
fi

sudo python3 - "$config_file" <<'PY'
import sys
from pathlib import Path

values = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        values[key] = value

if values.get("OPSPILOT_INTEGRATION_MODE", "").lower() != "draft":
    raise SystemExit("Safety stop: install while integration mode is draft")
project_key = values.get("OPSPILOT_JIRA_PROJECT_KEY", "")
if not project_key or not project_key.replace("_", "").isalnum():
    raise SystemExit("Safety stop: Jira project key is missing or invalid")
if values.get("OPSPILOT_JIRA_ISSUE_TYPE") != "INCIDENT":
    raise SystemExit("Safety stop: expected Jira issue type INCIDENT")
if len(values.get("OPSPILOT_ACTION_TOKEN", "")) < 24:
    raise SystemExit("Safety stop: action token is missing or invalid")
PY

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

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if sys.argv[2] != "200" or data.get("status") != "ready":
    print(json.dumps(data, indent=2))
    raise SystemExit("Integration validation is not ready")
if data.get("external_write_performed") is not False:
    raise SystemExit("Validation unexpectedly reported an external write")
if data.get("checks", {}).get("jira", {}).get("issue_type_name") != "INCIDENT":
    raise SystemExit("Validated Jira issue type is not INCIDENT")
if data.get("checks", {}).get("roster", {}).get("status") != "resolved":
    raise SystemExit("Current on-call roster is not resolved")
PY

sudo python3 - "$config_file" <<'PY'
import os
import secrets
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
prefix = "OPSPILOT_ACTION_TOKEN="
replacement = prefix + secrets.token_urlsafe(32)
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

sudo install -d -o root -g root -m 0750 /etc/opspilot-dashboard
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -d -o root -g root -m 0700 /var/lib/opspilot-cpu-alert
sudo install -o root -g root -m 0755 \
    "$files_dir/opspilot_cpu_alert.py" /usr/local/libexec/opspilot-cpu-alert
sudo install -o root -g root -m 0644 \
    "$files_dir/cpu-alert.env" /etc/opspilot-dashboard/cpu-alert.env
sudo install -o root -g root -m 0644 \
    "$files_dir/opspilot-cpu-alert.service" /etc/systemd/system/opspilot-cpu-alert.service
sudo install -o root -g root -m 0644 \
    "$files_dir/opspilot-cpu-alert.timer" /etc/systemd/system/opspilot-cpu-alert.timer
sudo install -o root -g root -m 0600 /dev/null /var/lib/opspilot-cpu-alert/state.json
sudo python3 - <<'PY'
import json
from pathlib import Path

state = {
    "version": 1,
    "high_streak": 0,
    "low_streak": 0,
    "incident_open": False,
    "idempotency_key": "",
    "jira_key": "",
    "last_cpu_percent": None,
    "last_sample_at": "",
    "last_dispatch_at": "",
    "last_error": "",
}
Path("/var/lib/opspilot-cpu-alert/state.json").write_text(
    json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

sudo systemctl daemon-reload
sudo systemctl enable --now opspilot-cpu-alert.timer
sudo systemctl start opspilot-cpu-alert.service

echo "OpsPilot automatic CPU controller: INSTALLED"
echo "Integration mode: DRAFT"
echo "External writes performed: false"
echo "Previously exposed action token: ROTATED (replacement not displayed)"
echo "Timer state: $(systemctl is-active opspilot-cpu-alert.timer)"
echo "Next step: run ./enable-live.sh when ready for one controlled Jira/Chat test."
