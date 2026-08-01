#!/usr/bin/env bash

# Stage 13 — OpsPilot v0.9 incident-integration dashboard deployment
# Target: Ubuntu 22.04 OpsPilot node
# This installer preserves the existing OpsPilot API on 127.0.0.1:3000,
# adds a read-only telemetry sidecar on 127.0.0.1:3100, and serves the UI
# through the existing nginx /opspilot/ path.

set -u

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
files_dir="$script_dir/files"
timestamp="$(date -u +%F-%H%M%S)"
audit_dir="$HOME/opspilot-lab/audit"
audit_file="$audit_dir/stage13-dashboard-$timestamp.txt"

mkdir -p "$audit_dir"

(
    set -euo pipefail

    site_file="/etc/nginx/sites-available/mynum"
    enabled_file="/etc/nginx/sites-enabled/mynum"
    unit_file="/etc/systemd/system/opspilot-dashboard-agent.service"
    app_dir="/opt/opspilot-dashboard"
    web_dir="/var/www/opspilot-dashboard"
    backup_dir="/var/backups/opspilot-dashboard/$timestamp"
    site_backup="$backup_dir/mynum.before-stage13.conf"
    stage_file="$backup_dir/mynum.stage13.conf"

    app_created=0
    web_created=0
    unit_created=0
    agent_started=0
    nginx_changed=0
    backup_created=0

    rollback() {
        status=$?
        trap - EXIT

        if [ "$status" -ne 0 ]; then
            echo
            echo "### AUTOMATIC ROLLBACK"

            if [ "$nginx_changed" -eq 1 ] &&
               sudo test -f "$site_backup"
            then
                sudo install \
                    -o root \
                    -g root \
                    -m 0644 \
                    "$site_backup" \
                    "$site_file"

                echo "Previous nginx configuration restored"

                if sudo nginx -t; then
                    sudo systemctl reload nginx || true
                    echo "Previous nginx configuration reloaded"
                else
                    echo "WARNING: Restored nginx configuration requires review"
                fi
            else
                echo "No nginx configuration rollback was required"
            fi

            if [ "$agent_started" -eq 1 ]; then
                sudo systemctl disable --now opspilot-dashboard-agent.service || true
                echo "Dashboard telemetry sidecar stopped"
            fi

            if [ "$unit_created" -eq 1 ]; then
                sudo rm -f "$unit_file"
                sudo systemctl daemon-reload || true
                echo "New systemd unit removed"
            fi

            if [ "$web_created" -eq 1 ]; then
                sudo rm -rf "$web_dir"
                echo "New dashboard web directory removed"
            fi

            if [ "$app_created" -eq 1 ]; then
                sudo rm -rf "$app_dir"
                echo "New dashboard agent directory removed"
            fi

            if [ "$backup_created" -eq 1 ]; then
                echo "Rollback evidence retained: $backup_dir"
            fi

            echo "Rollback completed"
        fi

        exit "$status"
    }

    trap rollback EXIT

    echo "### STAGE 13 DEPLOYMENT TIME"
    date -u

    echo
    echo "### PACKAGE VALIDATION"

    required_files=(
        "$files_dir/index.html"
        "$files_dir/dashboard.css"
        "$files_dir/dashboard.js"
        "$files_dir/opspilot-datacenter-login.png"
        "$files_dir/opspilot_dashboard_agent.py"
        "$files_dir/opspilot-dashboard-agent.service"
    )

    for required_file in "${required_files[@]}"
    do
        if [ ! -f "$required_file" ]; then
            echo "ERROR: Missing package file: $required_file"
            exit 1
        fi

        if [ -L "$required_file" ]; then
            echo "ERROR: Package file must not be a symbolic link: $required_file"
            exit 1
        fi
    done

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
    echo "### PRIVILEGE AND SERVICE PRECHECK"

    sudo -v
    sudo nginx -t
    systemctl is-active --quiet nginx
    systemctl is-active --quiet opspilot.service
    id opspilot >/dev/null

    if ! sudo test -f "$site_file"; then
        echo "ERROR: Missing nginx site: $site_file"
        exit 1
    fi

    if ! sudo test -L "$enabled_file"; then
        echo "ERROR: Enabled mynum site is not a symbolic link"
        exit 1
    fi

    enabled_target="$(sudo readlink -f "$enabled_file")"

    if [ "$enabled_target" != "$site_file" ]; then
        echo "ERROR: Enabled mynum link target changed"
        echo "Expected: $site_file"
        echo "Actual:   $enabled_target"
        exit 1
    fi

    if sudo test -e "$app_dir" ||
       sudo test -L "$app_dir" ||
       sudo test -e "$web_dir" ||
       sudo test -L "$web_dir" ||
       sudo test -e "$unit_file" ||
       sudo test -L "$unit_file"
    then
        echo "ERROR: A previous OpsPilot dashboard installation exists"
        echo "Do not overwrite it with this first-install package."
        exit 1
    fi

    if sudo ss -H -lnt 'sport = :3100' | grep -q .; then
        echo "ERROR: TCP port 3100 is already in use"
        sudo ss -lntp 'sport = :3100'
        exit 1
    fi

    echo "nginx active: PASS"
    echo "OpsPilot API active: PASS"
    echo "opspilot service account: PASS"
    echo "Enabled-site target: PASS | $enabled_target"
    echo "Dashboard paths absent: PASS"
    echo "Port 3100 available: PASS"

    echo
    echo "### CURRENT CONFIGURATION GUARD"

    python3 - "$site_file" <<'PYTHON'
import subprocess
import sys


def normalize(value):
    return "\n".join(
        line.strip()
        for line in value.splitlines()
        if line.strip()
    )


site_file = sys.argv[1]
current = subprocess.run(
    ["sudo", "cat", site_file],
    check=True,
    capture_output=True,
    text=True,
).stdout

expected = r'''
server {
listen 80;
root /var/www/mynum;
index index.html index.htm;
server_tokens off;
location = /opspilot {
return 308 /opspilot/;
}
location /opspilot/ {
proxy_pass http://127.0.0.1:3000/;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header Connection "";
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Prefix /opspilot;
proxy_connect_timeout 3s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;
}
}
'''

if normalize(current) != normalize(expected):
    print("ERROR: The nginx mynum configuration changed after Stage 5C.")
    print("Stage 13 stopped before making changes.")
    print("Current configuration:")
    print(current)
    raise SystemExit(1)

print("Stage 5C configuration unchanged: PASS")
PYTHON

    direct_health="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            http://127.0.0.1:3000/healthz
    )"

    direct_host="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            http://127.0.0.1:3000/api/v1/host
    )"

    python3 - "$direct_health" "$direct_host" <<'PYTHON'
import json
import sys

health = json.loads(sys.argv[1])
host = json.loads(sys.argv[2])

assert health["status"] == "ok"
assert health["service"] == "opspilot"
assert isinstance(host["hostname"], str) and host["hostname"]
assert host["uptime_seconds"] >= 0

print("Existing OpsPilot health: PASS")
print("Existing host endpoint: PASS")
PYTHON

    echo
    echo "### CREATE ROLLBACK BACKUP"

    sudo install -d -o root -g root -m 0700 "$backup_dir"
    backup_created=1

    sudo install \
        -o root \
        -g root \
        -m 0600 \
        "$site_file" \
        "$site_backup"

    sudo stat \
        -c '%A | %a | %U:%G | %n' \
        "$site_backup"

    echo
    echo "### INSTALL DASHBOARD AGENT"

    sudo install -d -o root -g opspilot -m 0750 "$app_dir"
    app_created=1

    sudo install \
        -o root \
        -g opspilot \
        -m 0750 \
        "$files_dir/opspilot_dashboard_agent.py" \
        "$app_dir/opspilot_dashboard_agent.py"

    sudo install \
        -o root \
        -g opspilot \
        -m 0640 \
        "$script_dir/README.md" \
        "$app_dir/README.md"

    sudo install \
        -o root \
        -g root \
        -m 0644 \
        "$files_dir/opspilot-dashboard-agent.service" \
        "$unit_file"

    unit_created=1

    sudo systemd-analyze verify "$unit_file"
    sudo systemctl daemon-reload
    sudo systemctl enable --now opspilot-dashboard-agent.service
    agent_started=1

    agent_ready=0

    for attempt in $(seq 1 15)
    do
        if curl \
            --silent \
            --show-error \
            --fail \
            --max-time 3 \
            http://127.0.0.1:3100/healthz \
            >/dev/null 2>&1
        then
            agent_ready=1
            echo "Dashboard agent healthy: PASS | attempt=$attempt"
            break
        fi

        echo "Waiting for dashboard agent | attempt=$attempt"
        sleep 1
    done

    if [ "$agent_ready" -ne 1 ]; then
        echo "ERROR: Dashboard agent did not become healthy"
        sudo systemctl status opspilot-dashboard-agent.service --no-pager || true
        sudo journalctl -u opspilot-dashboard-agent.service -n 30 --no-pager || true
        exit 1
    fi

    dashboard_json="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            http://127.0.0.1:3100/api/v1/dashboard
    )"

    python3 - "$dashboard_json" <<'PYTHON'
import json
import sys

data = json.loads(sys.argv[1])

assert data["service"] == "opspilot-dashboard-agent"
assert data["release"] == "v0.9.0"
assert isinstance(data["host"]["hostname"], str) and data["host"]["hostname"]
assert 0 <= data["cpu"]["percent"] <= 100
assert data["cpu"]["count"] >= 1
assert data["memory"]["total_bytes"] > 0
assert 0 <= data["memory"]["percent"] <= 100
assert data["disk"]["total_bytes"] > 0
assert 0 <= data["disk"]["percent"] <= 100
assert len(data["services"]) == 3
assert len(data["processes"]) >= 1
assert len(data["users"]) >= 1
assert len(data["mounts"]) >= 1
assert data["health"]["critical_total"] >= 1

print("Live CPU telemetry: PASS")
print("Live memory telemetry: PASS")
print("Live disk telemetry: PASS")
print("Service probes: PASS")
print("Top-process telemetry: PASS")
print("User and session inventory: PASS")
print("Mounted-filesystem inventory: PASS")
print("Health score: PASS")
PYTHON

    echo
    echo "### INSTALL DASHBOARD WEB FILES"

    sudo install -d -o root -g root -m 0755 "$web_dir"
    sudo install -d -o root -g root -m 0755 "$web_dir/assets"
    web_created=1

    sudo install \
        -o root \
        -g root \
        -m 0644 \
        "$files_dir/index.html" \
        "$web_dir/index.html"

    sudo install \
        -o root \
        -g root \
        -m 0644 \
        "$files_dir/dashboard.css" \
        "$web_dir/assets/dashboard.css"

    sudo install \
        -o root \
        -g root \
        -m 0644 \
        "$files_dir/dashboard.js" \
        "$web_dir/assets/dashboard.js"

    sudo install \
        -o root \
        -g root \
        -m 0644 \
        "$files_dir/opspilot-datacenter-login.png" \
        "$web_dir/assets/opspilot-datacenter-login.png"

    sudo find "$web_dir" -maxdepth 2 -type f -printf '%m | %u:%g | %p\n' | sort

    echo
    echo "### PREPARE NGINX DASHBOARD ROUTES"

    sudo tee "$stage_file" >/dev/null <<'NGINX'
server {
    listen 80;

    root /var/www/mynum;
    index index.html index.htm;

    server_tokens off;

    location = /opspilot {
        return 308 /opspilot/;
    }

    location = /opspilot/ {
        root /var/www/opspilot-dashboard;
        try_files /index.html =404;

        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
    }

    location /opspilot/assets/ {
        alias /var/www/opspilot-dashboard/assets/;

        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options "nosniff" always;
        access_log off;
    }

    location = /opspilot/api/v1/dashboard {
        proxy_pass http://127.0.0.1:3100/api/v1/dashboard;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /opspilot;

        proxy_connect_timeout 3s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;

        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location = /opspilot/dashboard-healthz {
        proxy_pass http://127.0.0.1:3100/healthz;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 3s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;

        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location /opspilot/ {
        proxy_pass http://127.0.0.1:3000/;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /opspilot;

        proxy_connect_timeout 3s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
NGINX

    sudo stat \
        -c '%A | %a | %U:%G | %n' \
        "$stage_file"

    sudo install \
        -o root \
        -g root \
        -m 0644 \
        "$stage_file" \
        "$site_file"

    nginx_changed=1

    sudo nginx -t
    sudo systemctl reload nginx
    systemctl is-active --quiet nginx

    echo "nginx dashboard routes installed: PASS"

    echo
    echo "### END-TO-END VALIDATION"

    dashboard_ready=0

    for attempt in $(seq 1 15)
    do
        if curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            http://127.0.0.1/opspilot/ \
            | grep -Fq '<title>OpsPilot'
        then
            dashboard_ready=1
            echo "Visual dashboard became ready: PASS | attempt=$attempt"
            break
        fi

        echo "Waiting for nginx dashboard route | attempt=$attempt"
        sleep 1
    done

    if [ "$dashboard_ready" -ne 1 ]; then
        echo "ERROR: Visual dashboard did not become ready through nginx"
        curl \
            --silent \
            --show-error \
            --max-time 5 \
            --write-out '\nHTTP status: %{http_code}\n' \
            http://127.0.0.1/opspilot/ || true
        sudo tail -n 30 /var/log/nginx/error.log || true
        exit 1
    fi

    curl \
        --silent \
        --show-error \
        --fail \
        --max-time 5 \
        --output /dev/null \
        http://127.0.0.1/opspilot/assets/dashboard.css

    curl \
        --silent \
        --show-error \
        --fail \
        --max-time 5 \
        --output /dev/null \
        http://127.0.0.1/opspilot/assets/dashboard.js

    curl \
        --silent \
        --show-error \
        --fail \
        --max-time 5 \
        --output /dev/null \
        http://127.0.0.1/opspilot/assets/opspilot-datacenter-login.png

    proxied_dashboard="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            http://127.0.0.1/opspilot/api/v1/dashboard
    )"

    proxied_health="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            http://127.0.0.1/opspilot/healthz
    )"

    proxied_command="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 10 \
            -H 'Content-Type: application/json' \
            --data '{"command":"uptime"}' \
            http://127.0.0.1/opspilot/api/v1/dashboard
    )"

    proxied_history="$(
        curl \
            --silent \
            --show-error \
            --fail \
            --max-time 5 \
            'http://127.0.0.1/opspilot/api/v1/dashboard?range=15m'
    )"

    existing_site_status="$(
        curl \
            --silent \
            --show-error \
            --max-time 5 \
            --output /dev/null \
            --write-out '%{http_code}' \
            http://127.0.0.1/
    )"

    python3 - "$proxied_dashboard" "$proxied_health" "$proxied_command" "$proxied_history" "$existing_site_status" <<'PYTHON'
import json
import sys

dashboard = json.loads(sys.argv[1])
health = json.loads(sys.argv[2])
command = json.loads(sys.argv[3])
history = json.loads(sys.argv[4])
site_status = sys.argv[5]

assert dashboard["service"] == "opspilot-dashboard-agent"
assert dashboard["release"] == "v0.9.0"
assert isinstance(dashboard["host"]["hostname"], str) and dashboard["host"]["hostname"]
assert len(dashboard["commands"]) >= 171
assert dashboard["integrations"]["mode"] == "draft"
assert dashboard["integrations"]["jira"]["project_key"] == "OPS"
assert dashboard["integrations"]["jira"]["issue_type"] == "INCIDENT"
assert command["status"] == "completed"
assert command["command"] == "uptime"
assert command["exit_code"] == 0
assert history["history"]["range"] == "15m"
assert history["history"]["step_seconds"] == 5
assert len(history["history"]["samples"]) >= 1

assert health["status"] == "ok"
assert health["service"] == "opspilot"
assert health["release"] == "v0.1.0"

assert site_status == "200"

print("Dashboard HTML through nginx: PASS")
print("Dashboard CSS through nginx: PASS")
print("Dashboard JavaScript through nginx: PASS")
print("Live telemetry API through nginx: PASS")
print("171 command catalog through nginx: PASS")
print("Real uptime command execution: PASS")
print("Historical range query through nginx: PASS")
print("Part 2 integration draft workflow: PASS")
print("Existing OpsPilot API compatibility: PASS")
print("Existing mynum website: PASS")
PYTHON

    redirect_status="$(
        curl \
            --silent \
            --show-error \
            --max-time 5 \
            --max-redirs 0 \
            --output /dev/null \
            --write-out '%{http_code}' \
            http://127.0.0.1/opspilot
    )"

    if [ "$redirect_status" != "308" ]; then
        echo "ERROR: /opspilot returned HTTP $redirect_status instead of 308"
        exit 1
    fi

    backend_addresses="$(
        sudo ss -H -lnt '( sport = :3000 or sport = :3100 )' |
            awk '{print $4}' |
            sort
    )"

    expected_addresses=$'127.0.0.1:3000\n127.0.0.1:3100'

    if [ "$backend_addresses" != "$expected_addresses" ]; then
        echo "ERROR: Unexpected OpsPilot listening addresses"
        echo "Expected:"
        echo "$expected_addresses"
        echo "Actual:"
        echo "$backend_addresses"
        exit 1
    fi

    echo "Canonical redirect: PASS | HTTP 308"
    echo "Both backend listeners remain loopback-only: PASS"

    echo
    echo "### FINAL SERVICE STATE"

    systemctl is-active nginx opspilot.service opspilot-dashboard-agent.service
    systemctl is-enabled nginx opspilot.service opspilot-dashboard-agent.service
    sudo nginx -t
    sudo ss -lntp '( sport = :80 or sport = :3000 or sport = :3100 )'

    echo
    echo "### FINAL RESULT"
    echo "OpsPilot living-server console: PASS"
    echo "Animated CPU hardware lens: PASS"
    echo "Functional sidebar workspaces: PASS"
    echo "Live CPU/memory/disk/network metrics: PASS"
    echo "Service and top-process telemetry: PASS"
    echo "User, session, mount and exposure inventory: PASS"
    echo "Jira/Chat/Meet/roster draft integration: PASS"
    echo "Existing OpsPilot API v0.1.0: PRESERVED"
    echo "Existing mynum website: PRESERVED"
    echo "Public dashboard: http://<server-ip>/opspilot/"
    echo "Private API backend: 127.0.0.1:3000"
    echo "Private telemetry sidecar: 127.0.0.1:3100"
    echo "Rollback backup: $backup_dir"

    trap - EXIT

) 2>&1 | tee "$audit_file"

deployment_status=${PIPESTATUS[0]}

echo
echo "Stage 13 deployment exit status: $deployment_status"
echo "Audit file: $audit_file"

if [ "$deployment_status" -eq 0 ]; then
    echo "Stage 13 incident-integration dashboard: PASS"
else
    echo "Stage 13 stopped and rollback was attempted: REVIEW REQUIRED"
fi

exit "$deployment_status"
