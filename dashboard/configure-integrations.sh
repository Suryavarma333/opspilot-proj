#!/usr/bin/env bash

# Configure OpsPilot integration secrets locally on the VM.
# Secrets are entered through hidden prompts and are never placed in shell history.

set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this script as the normal VM user, not as root."
    exit 1
fi

config_dir="/etc/opspilot-dashboard"
config_file="$config_dir/integrations.env"
temporary_file="$(mktemp)"
trap 'rm -f "$temporary_file"' EXIT

read -r -p "Jira site URL [https://your-domain.atlassian.net]: " jira_url
jira_url="${jira_url:-https://your-domain.atlassian.net}"
read -r -p "Jira integration account email: " jira_email
read -r -s -p "Jira API token (hidden): " jira_token
echo
read -r -p "Jira project key [OPS]: " jira_project
jira_project="${jira_project:-OPS}"
read -r -p "Jira issue type [INCIDENT]: " jira_issue_type
jira_issue_type="${jira_issue_type:-INCIDENT}"
read -r -p "Jira label [opspilot]: " jira_label
jira_label="${jira_label:-opspilot}"
read -r -p "Required Business Unit field ID [customfield_12345]: " business_unit_field
business_unit_field="${business_unit_field:-customfield_12345}"
read -r -s -p "Google Chat webhook URL (hidden): " chat_webhook
echo
read -r -p "Google Chat space label [NOC-Alerts]: " chat_space
chat_space="${chat_space:-NOC-Alerts}"
read -r -p "Google Meet bridge [https://meet.google.com/your-bridge]: " meet_url
meet_url="${meet_url:-https://meet.google.com/your-bridge}"

if [[ ! "$jira_url" =~ ^https://[A-Za-z0-9.-]+\.atlassian\.net/?$ ]]; then
    echo "The Jira URL must be an HTTPS atlassian.net site URL."
    exit 1
fi
if [[ ! "$jira_email" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]]; then
    echo "Invalid Jira integration account email."
    exit 1
fi
if [ "${#jira_token}" -lt 20 ]; then
    echo "The Jira API token is unexpectedly short."
    exit 1
fi
if [[ ! "$jira_project" =~ ^[A-Z][A-Z0-9_]{1,19}$ ]]; then
    echo "Invalid Jira project key."
    exit 1
fi
jira_issue_type_pattern='^[A-Za-z][-A-Za-z0-9_ ]{1,49}$'
if [[ ! "$jira_issue_type" =~ $jira_issue_type_pattern ]]; then
    echo "Invalid Jira issue type."
    exit 1
fi
if [[ ! "$jira_label" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
    echo "Invalid Jira label."
    exit 1
fi
if [[ ! "$business_unit_field" =~ ^customfield_[0-9]{1,30}$ ]]; then
    echo "Business Unit field must look like customfield_12345."
    exit 1
fi
if [[ ! "$chat_webhook" =~ ^https://chat\.googleapis\.com/ ]]; then
    echo "The Google Chat webhook must use https://chat.googleapis.com/."
    exit 1
fi
if [[ ! "$meet_url" =~ ^https://meet\.google\.com/[A-Za-z0-9-]+$ ]]; then
    echo "Invalid Google Meet bridge URL."
    exit 1
fi

action_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

umask 077
{
    printf 'OPSPILOT_INTEGRATION_MODE=draft\n'
    printf 'OPSPILOT_JIRA_URL=%s\n' "${jira_url%/}"
    printf 'OPSPILOT_JIRA_PROJECT_KEY=%s\n' "$jira_project"
    printf 'OPSPILOT_JIRA_REQUESTED_LABEL=%s\n' "$jira_label"
    printf 'OPSPILOT_JIRA_ISSUE_TYPE=%s\n' "$jira_issue_type"
    printf 'OPSPILOT_JIRA_BUSINESS_UNIT_FIELD_ID=%s\n' "$business_unit_field"
    printf 'OPSPILOT_GOOGLE_CHAT_SPACE=%s\n' "$chat_space"
    printf 'OPSPILOT_MEET_URL=%s\n' "$meet_url"
    printf 'OPSPILOT_ROSTER_CSV_PATH=/var/lib/opspilot-dashboard-agent/current-oncall.csv\n'
    printf 'OPSPILOT_JIRA_EMAIL=%s\n' "$jira_email"
    printf 'OPSPILOT_JIRA_API_TOKEN=%s\n' "$jira_token"
    printf 'OPSPILOT_CHAT_WEBHOOK_URL=%s\n' "$chat_webhook"
    printf 'OPSPILOT_ACTION_TOKEN=%s\n' "$action_token"
} >"$temporary_file"

sudo install -d -o root -g root -m 0750 "$config_dir"
sudo install -o root -g root -m 0600 "$temporary_file" "$config_file"
sudo systemctl restart opspilot-dashboard-agent.service

echo
echo "Credentials stored with root-only permissions."
echo "Integration mode remains DRAFT; no Jira or Google Chat write is enabled."
echo "Save this one-time action token in your approved password manager:"
echo "$action_token"
echo
echo "Read-only validation response:"
curl --silent --show-error --max-time 15 \
    -H 'Content-Type: application/json' \
    --data '{}' \
    http://127.0.0.1:3100/api/v1/integrations/validate \
    | python3 -m json.tool
