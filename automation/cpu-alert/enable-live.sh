#!/usr/bin/env bash

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this command as the normal VM user, not with sudo."
    exit 1
fi

config_file="/etc/opspilot-dashboard/integrations.env"
validation_file="$(mktemp)"
trap 'rm -f "$validation_file"' EXIT

for command_name in curl python3 sudo systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Required command is missing: $command_name"
        exit 1
    }
done

sudo -v

if ! sudo test -f "$config_file"; then
    echo "OpsPilot integration configuration was not found: $config_file"
    exit 1
fi

if ! sudo systemctl list-unit-files \
    opspilot-cpu-alert.timer \
    --no-legend 2>/dev/null | grep -q '^opspilot-cpu-alert.timer'; then
    echo "OpsPilot CPU controller is not installed."
    echo "Run ./install.sh successfully before enabling live mode."
    exit 1
fi

if ! sudo test -s /var/lib/opspilot-cpu-alert/state.json; then
    echo "OpsPilot CPU controller state is missing."
    echo "Run ./install.sh successfully before enabling live mode."
    exit 1
fi

echo "This enables automatic Jira creation and Google Chat notification."
echo "CPU >= 90% for approximately 60 seconds will perform external writes."
read -r -p "Type ENABLE-LIVE to continue: " confirmation
if [ "$confirmation" != "ENABLE-LIVE" ]; then
    echo "Live mode was not enabled."
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

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if sys.argv[2] != "200" or data.get("status") != "ready":
    print(json.dumps(data, indent=2))
    raise SystemExit("Integration validation is not ready; live mode not enabled")
if data.get("external_write_performed") is not False:
    raise SystemExit("Validation unexpectedly reported an external write")
PY

sudo systemctl stop opspilot-cpu-alert.timer

sudo python3 - "$config_file" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
prefix = "OPSPILOT_INTEGRATION_MODE="
found = False
updated = []
for line in lines:
    if line.startswith(prefix):
        if not found:
            updated.append(prefix + "live")
            found = True
        continue
    updated.append(line)
if not found:
    updated.append(prefix + "live")

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

sudo python3 - <<'PY'
import json
from pathlib import Path

path = Path("/var/lib/opspilot-cpu-alert/state.json")
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
path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY

sudo systemctl restart opspilot-dashboard-agent.service
for _attempt in $(seq 1 20); do
    if curl --fail --silent --max-time 3 http://127.0.0.1:3100/healthz >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

status_json="$(curl --fail --silent --show-error --max-time 10 \
    http://127.0.0.1:3100/api/v1/integrations/status)"
python3 - "$status_json" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
if data.get("mode") != "live" or data.get("external_writes_enabled") is not True:
    raise SystemExit("OpsPilot did not enter live mode")
print("OpsPilot integration mode: LIVE")
print("Automatic external writes: ENABLED")
PY

sudo systemctl enable --now opspilot-cpu-alert.timer
echo "Controller timer: $(systemctl is-active opspilot-cpu-alert.timer)"
echo "You may now run ./test-high-cpu.sh"
