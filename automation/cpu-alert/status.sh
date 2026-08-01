#!/usr/bin/env bash

set -euo pipefail

echo "Integration status:"
if status_json="$(curl --fail --silent --show-error --max-time 10 \
    http://127.0.0.1:3100/api/v1/integrations/status)"; then
    python3 -m json.tool <<<"$status_json"
else
    echo "UNAVAILABLE: OpsPilot dashboard agent did not answer on 127.0.0.1:3100"
fi
echo
echo "Timer: $(systemctl is-active opspilot-cpu-alert.timer 2>/dev/null || true)"
echo "Controller state:"
if ! sudo test -s /var/lib/opspilot-cpu-alert/state.json; then
    echo "NOT INSTALLED: /var/lib/opspilot-cpu-alert/state.json is absent"
    exit 0
fi

sudo python3 - <<'PY'
import json
from pathlib import Path

path = Path("/var/lib/opspilot-cpu-alert/state.json")
data = json.loads(path.read_text(encoding="utf-8"))
safe = {
    key: data.get(key)
    for key in (
        "high_streak",
        "low_streak",
        "incident_open",
        "jira_key",
        "last_cpu_percent",
        "last_sample_at",
        "last_dispatch_at",
        "last_error",
    )
}
print(json.dumps(safe, indent=2))
PY
