#!/usr/bin/env bash

# Configure the optional OpsPilot OpenAI Responses API adapter without
# changing Jira, Chat, roster, or action-token settings.

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this script as the normal VM user, not as root."
    exit 1
fi

config_file="/etc/opspilot-dashboard/integrations.env"
temporary_file="$(mktemp)"
key_file="$(mktemp)"
trap 'rm -f "$temporary_file" "$key_file"' EXIT

sudo test -f "$config_file" || {
    echo "Configure the dashboard integrations file before adding AI settings."
    exit 1
}

read -r -p "OpenAI model [gpt-5.6-sol]: " ai_model
ai_model="${ai_model:-gpt-5.6-sol}"
read -r -s -p "OpenAI API key (hidden; leave empty to use local fallback): " ai_key
echo

if [[ ! "$ai_model" =~ ^[A-Za-z0-9._-]{2,80}$ ]]; then
    echo "Invalid model identifier."
    exit 1
fi
if [ -n "$ai_key" ] && [ "${#ai_key}" -lt 20 ]; then
    echo "The API key is unexpectedly short."
    exit 1
fi
umask 077
printf '%s' "$ai_key" >"$key_file"
unset ai_key

sudo python3 - "$config_file" "$temporary_file" "$ai_model" "$key_file" <<'PYTHON'
import os
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
model = sys.argv[3]
api_key = Path(sys.argv[4]).read_text(encoding="utf-8")

updates = {
    "OPSPILOT_AI_MODEL": model,
    "OPSPILOT_AI_BASE_URL": "https://api.openai.com/v1",
    "OPSPILOT_AI_TIMEOUT_SECONDS": "30",
    "OPSPILOT_REMEDIATION_MODE": "draft",
    "OPSPILOT_AI_API_KEY": api_key,
}

lines = source.read_text(encoding="utf-8").splitlines()
output = []
seen = set()
for line in lines:
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in updates:
        if key not in seen:
            output.append(f"{key}={updates[key]}")
            seen.add(key)
    else:
        output.append(line)
for key, value in updates.items():
    if key not in seen:
        output.append(f"{key}={value}")
target.write_text("\n".join(output) + "\n", encoding="utf-8")
os.chmod(target, 0o600)
PYTHON

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/opspilot-dashboard/ai-config-$timestamp"
sudo install -d -o root -g root -m 0700 "$backup_dir"
sudo install -o root -g root -m 0600 "$config_file" "$backup_dir/integrations.env.before"
sudo install -o root -g root -m 0600 "$temporary_file" "$config_file"
sudo systemctl restart opspilot-dashboard-agent.service

echo
echo "OpsPilot AI configuration: UPDATED"
echo "Model: $ai_model"
provider_mode="$(sudo python3 - "$config_file" <<'PYTHON'
import sys
from pathlib import Path
configured = any(
    line.startswith("OPSPILOT_AI_API_KEY=") and len(line.split("=", 1)[1]) >= 20
    for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
)
print("openai_responses" if configured else "deterministic_fallback")
PYTHON
)"
echo "Provider mode: $provider_mode"
echo "Remediation mode: DRAFT"
echo "Backup: $backup_dir"
curl --silent --show-error --fail --max-time 10 \
    http://127.0.0.1:3100/api/v1/ai/status \
    | python3 -m json.tool
