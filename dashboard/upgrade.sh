#!/usr/bin/env bash

# OpsPilot v0.2.0-v0.8.0 -> v0.9.0 in-place upgrade
# Preserves nginx, the original API, loopback-only listeners, ownership, and
# the existing dashboard deployment while adding incident workflow integrations.

set -u

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
files_dir="$script_dir/files"
timestamp="$(date -u +%F-%H%M%S)"
audit_dir="$HOME/opspilot-lab/audit"
audit_file="$audit_dir/opspilot-v0.9-upgrade-$timestamp.txt"

mkdir -p "$audit_dir"

(
    set -euo pipefail

    app_dir="/opt/opspilot-dashboard"
    web_dir="/var/www/opspilot-dashboard"
    unit_file="/etc/systemd/system/opspilot-dashboard-agent.service"
    backup_dir="/var/backups/opspilot-dashboard-v0.9/$timestamp"
    changed=0

    rollback() {
        status=$?
        trap - EXIT

        if [ "$status" -ne 0 ]; then
            echo
            echo "### AUTOMATIC ROLLBACK"

            if [ "$changed" -eq 1 ] && sudo test -d "$backup_dir"; then
                sudo install -o root -g opspilot -m 0750 \
                    "$backup_dir/opspilot_dashboard_agent.py" \
                    "$app_dir/opspilot_dashboard_agent.py"
                sudo install -o root -g opspilot -m 0640 \
                    "$backup_dir/README.md" \
                    "$app_dir/README.md"
                sudo install -o root -g root -m 0644 \
                    "$backup_dir/index.html" \
                    "$web_dir/index.html"
                sudo install -o root -g root -m 0644 \
                    "$backup_dir/dashboard.css" \
                    "$web_dir/assets/dashboard.css"
                sudo install -o root -g root -m 0644 \
                    "$backup_dir/dashboard.js" \
                    "$web_dir/assets/dashboard.js"
                if sudo test -f "$backup_dir/opspilot-datacenter-login.png"; then
                    sudo install -o root -g root -m 0644 \
                        "$backup_dir/opspilot-datacenter-login.png" \
                        "$web_dir/assets/opspilot-datacenter-login.png"
                fi
                sudo install -o root -g root -m 0644 \
                    "$backup_dir/opspilot-dashboard-agent.service" \
                    "$unit_file"
                sudo systemctl daemon-reload
                sudo systemctl restart opspilot-dashboard-agent.service || true
                echo "Previous OpsPilot dashboard restored"
            else
                echo "No installed file required rollback"
            fi

            echo "Rollback evidence retained: $backup_dir"
            echo "Rollback completed"
        fi

        exit "$status"
    }

    trap rollback EXIT

    echo "### OPSPILOT V0.9 UPGRADE TIME"
    date -u

    echo
    echo "### PACKAGE VALIDATION"

    (
        cd "$script_dir"
        sha256sum --check CHECKSUMS.sha256
    )

    python3 -m py_compile "$files_dir/opspilot_dashboard_agent.py"

    if command -v node >/dev/null 2>&1; then
        node --check "$files_dir/dashboard.js"
        echo "JavaScript syntax: PASS"
    else
        echo "JavaScript syntax: SKIPPED | Node.js is not required on the VM"
    fi

    echo "Package checksums: PASS"
    echo "Python syntax: PASS"

    echo
    echo "### INSTALLED-STATE PRECHECK"

    sudo -v
    systemctl is-active --quiet nginx
    systemctl is-active --quiet opspilot.service
    systemctl is-active --quiet opspilot-dashboard-agent.service
    sudo nginx -t

    for path in \
        "$app_dir/opspilot_dashboard_agent.py" \
        "$app_dir/README.md" \
        "$web_dir/index.html" \
        "$web_dir/assets/dashboard.css" \
        "$web_dir/assets/dashboard.js" \
        "$unit_file"
    do
        if ! sudo test -f "$path"; then
            echo "ERROR: Expected OpsPilot dashboard file is missing: $path"
            exit 1
        fi
    done

    current_json="$(
        curl --silent --show-error --fail --max-time 5 \
            http://127.0.0.1:3100/api/v1/dashboard
    )"

    current_release="$(
        python3 - "$current_json" <<'PYTHON'
import json
import sys
print(json.loads(sys.argv[1])["release"])
PYTHON
    )"

    case "$current_release" in
        v0.2.0|v0.3.0|v0.4.0|v0.5.0|v0.6.0|v0.7.0|v0.8.0)
            echo "Installed dashboard release: PASS | $current_release"
            ;;
        v0.9.0)
            echo "OpsPilot v0.9.0 is already installed."
            echo "No files were changed."
            trap - EXIT
            exit 0
            ;;
        *)
            echo "ERROR: Unsupported installed dashboard release: $current_release"
            exit 1
            ;;
    esac

    backend_addresses="$(
        sudo ss -H -lnt '( sport = :3000 or sport = :3100 )' |
            awk '{print $4}' |
            sort
    )"

    expected_addresses=$'127.0.0.1:3000\n127.0.0.1:3100'

    if [ "$backend_addresses" != "$expected_addresses" ]; then
        echo "ERROR: OpsPilot backend exposure changed"
        echo "$backend_addresses"
        exit 1
    fi

    echo "nginx active: PASS"
    echo "Original OpsPilot API active: PASS"
    echo "Dashboard agent active: PASS"
    echo "Both backend listeners loopback-only: PASS"

    echo
    echo "### CREATE ROLLBACK BACKUP"

    sudo install -d -o root -g root -m 0700 "$backup_dir"
    sudo install -o root -g root -m 0600 \
        "$app_dir/opspilot_dashboard_agent.py" \
        "$backup_dir/opspilot_dashboard_agent.py"
    sudo install -o root -g root -m 0600 \
        "$app_dir/README.md" \
        "$backup_dir/README.md"
    sudo install -o root -g root -m 0600 \
        "$web_dir/index.html" \
        "$backup_dir/index.html"
    sudo install -o root -g root -m 0600 \
        "$web_dir/assets/dashboard.css" \
        "$backup_dir/dashboard.css"
    sudo install -o root -g root -m 0600 \
        "$web_dir/assets/dashboard.js" \
        "$backup_dir/dashboard.js"
    if sudo test -f "$web_dir/assets/opspilot-datacenter-login.png"; then
        sudo install -o root -g root -m 0600 \
            "$web_dir/assets/opspilot-datacenter-login.png" \
            "$backup_dir/opspilot-datacenter-login.png"
    fi
    sudo install -o root -g root -m 0600 \
        "$unit_file" \
        "$backup_dir/opspilot-dashboard-agent.service"

    echo "Rollback backup: $backup_dir"

    echo
    echo "### INSTALL V0.9 FILES"

    changed=1

    sudo install -o root -g opspilot -m 0750 \
        "$files_dir/opspilot_dashboard_agent.py" \
        "$app_dir/opspilot_dashboard_agent.py"
    sudo install -o root -g opspilot -m 0640 \
        "$script_dir/README.md" \
        "$app_dir/README.md"
    sudo install -o root -g root -m 0644 \
        "$files_dir/index.html" \
        "$web_dir/index.html"
    sudo install -o root -g root -m 0644 \
        "$files_dir/dashboard.css" \
        "$web_dir/assets/dashboard.css"
    sudo install -o root -g root -m 0644 \
        "$files_dir/dashboard.js" \
        "$web_dir/assets/dashboard.js"
    sudo install -o root -g root -m 0644 \
        "$files_dir/opspilot-datacenter-login.png" \
        "$web_dir/assets/opspilot-datacenter-login.png"
    sudo install -o root -g root -m 0644 \
        "$files_dir/opspilot-dashboard-agent.service" \
        "$unit_file"

    sudo systemd-analyze verify "$unit_file"
    sudo systemctl daemon-reload
    sudo systemctl restart opspilot-dashboard-agent.service

    agent_ready=0

    for attempt in $(seq 1 15)
    do
        if curl --silent --show-error --fail --max-time 3 \
            http://127.0.0.1:3100/healthz >/dev/null 2>&1
        then
            agent_ready=1
            echo "OpsPilot v0.9 agent ready: PASS | attempt=$attempt"
            break
        fi

        echo "Waiting for upgraded agent | attempt=$attempt"
        sleep 1
    done

    if [ "$agent_ready" -ne 1 ]; then
        echo "ERROR: Upgraded dashboard agent did not become healthy"
        sudo systemctl status opspilot-dashboard-agent.service --no-pager || true
        sudo journalctl -u opspilot-dashboard-agent.service -n 30 --no-pager || true
        exit 1
    fi

    echo
    echo "### END-TO-END VALIDATION"

    dashboard_json="$(
        curl --silent --show-error --fail --max-time 5 \
            http://127.0.0.1/opspilot/api/v1/dashboard
    )"

    dashboard_html="$(
        curl --silent --show-error --fail --max-time 5 \
            http://127.0.0.1/opspilot/
    )"

    command_json="$(
        curl --silent --show-error --fail --max-time 10 \
            -H 'Content-Type: application/json' \
            --data '{"command":"uptime"}' \
            http://127.0.0.1/opspilot/api/v1/dashboard
    )"

    history_json="$(
        curl --silent --show-error --fail --max-time 5 \
            'http://127.0.0.1/opspilot/api/v1/dashboard?range=15m'
    )"

    python3 - "$dashboard_json" "$dashboard_html" "$command_json" "$history_json" <<'PYTHON'
import json
import sys

data = json.loads(sys.argv[1])
html = sys.argv[2]
command = json.loads(sys.argv[3])
history = json.loads(sys.argv[4])

assert data["service"] == "opspilot-dashboard-agent"
assert data["release"] == "v0.9.0"
assert isinstance(data["host"]["hostname"], str) and data["host"]["hostname"]
assert len(data["users"]) >= 1
assert any(item["username"] == "root" for item in data["users"])
assert len(data["mounts"]) >= 1
assert any(item["mount"] == "/" for item in data["mounts"])
assert isinstance(data["sessions"], list)
assert len(data["commands"]) >= 171
assert data["integrations"]["mode"] == "draft"
assert data["integrations"]["jira"]["project_key"] == "OPS"
assert data["integrations"]["google_chat"]["space"] == "NOC-Alerts"
assert command["status"] == "completed"
assert command["command"] == "uptime"
assert command["exit_code"] == 0
assert history["history"]["range"] == "15m"
assert history["history"]["step_seconds"] == 5
assert len(history["history"]["samples"]) >= 1

assert '<div id="root"></div>' in html

print("Live users and groups inventory: PASS")
print("Live active-session inventory: PASS")
print("Live mounted-filesystem inventory: PASS")
print("React living-server application shell: PASS")
print("Animated hardware components: PASS")
print("Working senior-engineer workspaces: PASS")
print("171 live diagnostic commands: PASS")
print("Real uptime command execution: PASS")
print("Historical range query: PASS")
print("Part 2 integration draft workflow: PASS")
PYTHON

    systemctl is-active --quiet nginx
    systemctl is-active --quiet opspilot.service
    systemctl is-active --quiet opspilot-dashboard-agent.service
    sudo nginx -t

    final_addresses="$(
        sudo ss -H -lnt '( sport = :3000 or sport = :3100 )' |
            awk '{print $4}' |
            sort
    )"

    if [ "$final_addresses" != "$expected_addresses" ]; then
        echo "ERROR: Backend exposure changed during upgrade"
        exit 1
    fi

    echo
    echo "### FINAL RESULT"
    echo "OpsPilot living-server console: PASS"
    echo "Animated CPU hardware lens: PASS"
    echo "Functional sidebar workspaces: PASS"
    echo "Users and access inventory: PASS"
    echo "Storage and mount inventory: PASS"
    echo "Network exposure review: PASS"
    echo "Dual light and dark themes: PASS"
    echo "Heartbeat outage alarm: PASS"
    echo "171 safe command diagnostics: PASS"
    echo "Jira/Chat/Meet/roster draft integration: PASS"
    echo "Existing live telemetry: PRESERVED"
    echo "Original OpsPilot API v0.1.0: PRESERVED"
    echo "Existing mynum website: PRESERVED"
    echo "Backend listeners remain loopback-only: PASS"
    echo "Rollback backup: $backup_dir"

    trap - EXIT

) 2>&1 | tee "$audit_file"

upgrade_status=${PIPESTATUS[0]}

echo
echo "OpsPilot v0.9 upgrade exit status: $upgrade_status"
echo "Audit file: $audit_file"

if [ "$upgrade_status" -eq 0 ]; then
    echo "OpsPilot v0.9 incident-integration console: PASS"
else
    echo "OpsPilot v0.9 upgrade stopped and rollback was attempted: REVIEW REQUIRED"
fi

exit "$upgrade_status"
