#!/usr/bin/env python3
"""OpsPilot dashboard telemetry sidecar.

Reads Linux telemetry from procfs, a small fixed set of systemd units, and a
reviewed allowlist of non-mutating diagnostic commands. The listener remains
deliberately loopback-only.
"""

from __future__ import annotations

import datetime as dt
import base64
import csv
import glob
import grp
import io
import json
import os
import platform
import pwd
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

from opspilot_ai_engine import AutonomousRCAManager, OpsPilotAIEngine


RELEASE = "v1.0.0"
LISTEN_ADDRESS = "127.0.0.1"
LISTEN_PORT = 3100
SERVICE_NAMES = ("nginx.service", "opspilot.service", "myname.timer")
MAX_PROCESS_ROWS = 8
MAX_USER_ROWS = 24
MAX_MOUNT_ROWS = 16
COMMAND_TIMEOUT_SECONDS = 8
COMMAND_OUTPUT_LIMIT = 65536
METRIC_SAMPLE_SECONDS = 5
# Keep enough local history for the longest fixed dashboard range. The store
# remains bounded and is downsampled by RANGE_CONFIG before data reaches React.
METRIC_RETENTION_SECONDS = 16 * 24 * 60 * 60
METRICS_DB_PATH = Path(
    os.environ.get(
        "OPSPILOT_METRICS_DB",
        "/tmp/opspilot-dashboard-metrics.sqlite3",
    )
)
INTEGRATION_DB_PATH = Path(
    os.environ.get(
        "OPSPILOT_INTEGRATION_DB",
        "/tmp/opspilot-dashboard-integrations.sqlite3",
    )
)
INTEGRATION_MODE = os.environ.get("OPSPILOT_INTEGRATION_MODE", "draft").strip().lower()
JIRA_URL = os.environ.get(
    "OPSPILOT_JIRA_URL", "https://your-domain.atlassian.net"
).rstrip("/")
JIRA_PROJECT_KEY = os.environ.get("OPSPILOT_JIRA_PROJECT_KEY", "OPS").strip().upper()
JIRA_REQUESTED_LABEL = os.environ.get("OPSPILOT_JIRA_REQUESTED_LABEL", "opspilot").strip()
JIRA_ISSUE_TYPE = os.environ.get("OPSPILOT_JIRA_ISSUE_TYPE", "INCIDENT").strip()
# OpsPilot Jira Business Unit fix v1.0.0
JIRA_BUSINESS_UNIT_FIELD_ID = os.environ.get(
    "OPSPILOT_JIRA_BUSINESS_UNIT_FIELD_ID", ""
).strip()
JIRA_BUSINESS_UNIT_OPTION_ID = os.environ.get(
    "OPSPILOT_JIRA_BUSINESS_UNIT_OPTION_ID", ""
).strip()
JIRA_BUSINESS_UNIT_MULTIPLE = os.environ.get(
    "OPSPILOT_JIRA_BUSINESS_UNIT_MULTIPLE", "false"
).strip().lower() == "true"
GOOGLE_CHAT_SPACE = os.environ.get("OPSPILOT_GOOGLE_CHAT_SPACE", "NOC-Alerts").strip()
MEET_URL = os.environ.get(
    "OPSPILOT_MEET_URL", "https://meet.google.com/your-bridge"
).strip()
ROSTER_SHEET_ID = os.environ.get("OPSPILOT_ROSTER_SHEET_ID", "").strip()
ROSTER_SHEET_GID = os.environ.get("OPSPILOT_ROSTER_SHEET_GID", "0").strip()
ROSTER_CSV_PATH = os.environ.get("OPSPILOT_ROSTER_CSV_PATH", "").strip()
JIRA_EMAIL = os.environ.get("OPSPILOT_JIRA_EMAIL", "").strip()
JIRA_API_TOKEN = os.environ.get("OPSPILOT_JIRA_API_TOKEN", "").strip()
CHAT_WEBHOOK_URL = os.environ.get("OPSPILOT_CHAT_WEBHOOK_URL", "").strip()
ACTION_TOKEN = os.environ.get("OPSPILOT_ACTION_TOKEN", "")
EXTERNAL_REQUEST_TIMEOUT_SECONDS = 10
EXTERNAL_RESPONSE_LIMIT = 1024 * 1024
RANGE_CONFIG: dict[str, tuple[int, int]] = {
    "15m": (15 * 60, 5),
    "30m": (30 * 60, 10),
    "1h": (60 * 60, 20),
    "3h": (3 * 60 * 60, 60),
    "6h": (6 * 60 * 60, 120),
    "12h": (12 * 60 * 60, 5 * 60),
    "24h": (24 * 60 * 60, 10 * 60),
    "7d": (7 * 24 * 60 * 60, 60 * 60),
    "15d": (15 * 24 * 60 * 60, 2 * 60 * 60),
}

ALLOWED_COMMANDS = frozenset(
    line.strip()
    for line in """
uptime
uptime -p
uptime -s
hostname
hostname -f
hostname -I
hostnamectl
uname -a
uname -r
uname -m
cat /etc/os-release
cat /proc/version
cat /proc/cmdline
cat /proc/uptime
timedatectl
date -u
who -b
systemd-detect-virt
lsb_release -a
lscpu
nproc --all
cat /proc/cpuinfo
cat /proc/loadavg
cat /proc/pressure/cpu
cat /proc/pressure/memory
cat /proc/pressure/io
cat /proc/interrupts
cat /proc/softirqs
cat /proc/sys/fs/file-nr
cat /proc/sys/fs/inode-nr
vmstat 1 2
vmstat -s
vmstat -a
vmstat -m
mpstat -P ALL 1 1
pidstat 1 1
top
top -b -n 1
journalctl -p 3 -xb -n 50 --no-pager
getconf CLK_TCK
free -h
free -w -h
cat /proc/meminfo
swapon --show
ps -eo pid,ppid,user,stat,pcpu,pmem,comm --sort=-pcpu
ps -eo pid,psr,stat,comm
ps -eo pid,user,pmem,rss,vsz,comm --sort=-rss
pmap -x 1
cat /proc/1/status
sysctl vm.swappiness
sysctl vm.overcommit_memory
sysctl vm.dirty_ratio
sysctl vm.min_free_kbytes
lsblk
lsblk -f
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS
lsblk --json -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS
df -hT
df -ih
findmnt
findmnt -D
findmnt /
findmnt --verify
mount
cat /proc/mounts
cat /proc/diskstats
stat -f /
du -xhd1 /var
du -xhd1 /home
iostat -xz 1 1
blkid
ls -lah /var/log
journalctl --disk-usage
journalctl --verify
ip -br address
ip -br link
ip address show
ip -s link
ip -details link show
ip route show
ip -6 route show
ip rule show
ip neigh show
ss -lntup
ss -s
ss -tan state established
ss -tan state time-wait
ss -o state established
cat /proc/net/dev
cat /proc/net/route
cat /etc/resolv.conf
resolvectl status
getent hosts localhost
sysctl net.ipv4.ip_forward
sysctl net.ipv4.tcp_syncookies
sysctl net.core.somaxconn
ps aux
ps -ef
ps -e --forest
ps -eo pid,ppid,lstart,etime,stat,comm
ps -eo state,pid,comm | sort
pgrep -a nginx
pgrep -a python
pgrep -a sshd
cat /proc/1/cgroup
cat /proc/1/limits
ls -l /proc/1/fd
lsns
systemd-cgls
systemd-cgtop -b -n 1
ulimit -a
systemctl --failed --no-pager
systemctl list-units --type=service --state=running --no-pager
systemctl list-units --type=service --state=failed --no-pager
systemctl list-unit-files --type=service --no-pager
systemctl list-timers --all --no-pager
systemctl status nginx --no-pager
systemctl status opspilot.service --no-pager
systemctl status opspilot-dashboard-agent.service --no-pager
systemctl status unattended-upgrades --no-pager
systemctl show nginx -p ActiveState,SubState,MainPID,MemoryCurrent
systemctl show opspilot.service -p ActiveState,SubState,MainPID,MemoryCurrent
systemctl is-system-running
systemctl list-dependencies nginx --no-pager
systemctl list-sockets --no-pager
systemd-analyze
systemd-analyze blame
systemd-analyze critical-chain
systemd-analyze security opspilot-dashboard-agent.service
loginctl list-sessions --no-pager
loginctl list-users --no-pager
journalctl -p err -n 50 --no-pager
journalctl -p warning -n 80 --no-pager
journalctl -b -n 100 --no-pager
journalctl -b -1 -n 80 --no-pager
journalctl -u nginx -n 80 --no-pager
journalctl -u opspilot.service -n 80 --no-pager
journalctl -u opspilot-dashboard-agent.service -n 80 --no-pager
journalctl -u unattended-upgrades -n 50 --no-pager
journalctl -k -n 80 --no-pager
journalctl --since '1 hour ago' --no-pager
journalctl --list-boots --no-pager
dmesg --level=err,warn
tail -n 80 /var/log/auth.log
tail -n 80 /var/log/syslog
last -n 20
lastb -n 20
who
w
users
lastlog
getent passwd
getent group
getent group sudo
awk -F: '$3==0 {print $1}' /etc/passwd
awk -F: '$7 !~ /(nologin|false)$/ {print $1,$7}' /etc/passwd
stat /etc/passwd /etc/group /etc/sudoers
ls -la /etc/sudoers.d
sshd -T
grep -Ev '^(#|$)' /etc/ssh/sshd_config
sysctl kernel.randomize_va_space
sysctl kernel.kptr_restrict
sysctl fs.protected_hardlinks
sysctl fs.protected_symlinks
find /tmp -xdev -type f -perm -0002 -ls
dpkg-query -W
dpkg -l
apt list --upgradable
apt-cache policy
grep -Rh '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d
ls -1 /boot/vmlinuz-*
test -f /var/run/reboot-required && cat /var/run/reboot-required || echo no
""".splitlines()
    if line.strip()
)


def read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def bytes_from_kib(value: str) -> int:
    return int(value.split()[0]) * 1024


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def local_datetime(epoch_seconds: float) -> str:
    return dt.datetime.fromtimestamp(epoch_seconds).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _safe_text(value: Any, maximum: int = 240) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.replace("\x00", "").split())[:maximum]


def _external_json(
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("External integration endpoints must use an explicit HTTPS URL")
    body = None
    request_headers = {
        "Accept": "application/json",
        "User-Agent": f"OpsPilot/{RELEASE}",
    }
    if headers:
        request_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=request_headers, method=method)
    try:
        with urlopen(request, timeout=EXTERNAL_REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read(EXTERNAL_RESPONSE_LIMIT + 1)
            if len(raw) > EXTERNAL_RESPONSE_LIMIT:
                raise ValueError("External integration response exceeded the safety limit")
            parsed_body = json.loads(raw.decode("utf-8")) if raw else {}
            return response.status, parsed_body if isinstance(parsed_body, dict) else {"data": parsed_body}
    except HTTPError as error:
        raw = error.read(EXTERNAL_RESPONSE_LIMIT)
        try:
            detail = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            detail = {"message": raw.decode("utf-8", errors="replace")[:500]}
        raise RuntimeError(f"External service returned HTTP {error.code}: {detail}") from error
    except URLError as error:
        raise RuntimeError(f"External service could not be reached: {error.reason}") from error


def _jira_headers() -> dict[str, str]:
    if not JIRA_EMAIL or not JIRA_API_TOKEN:
        raise RuntimeError("Jira credentials are not configured")
    encoded = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_TOKEN}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def _jira_project() -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,19}", JIRA_PROJECT_KEY):
        raise RuntimeError("The configured Jira project key is not valid")
    _, project = _external_json(
        "GET",
        f"{JIRA_URL}/rest/api/3/project/{JIRA_PROJECT_KEY}",
        headers=_jira_headers(),
    )
    issue_types = project.get("issueTypes") if isinstance(project.get("issueTypes"), list) else []
    matching_type = next(
        (
            item
            for item in issue_types
            if isinstance(item, dict)
            and str(item.get("name", "")).casefold() == JIRA_ISSUE_TYPE.casefold()
        ),
        None,
    )
    if matching_type is None:
        raise RuntimeError(
            f"Jira project {JIRA_PROJECT_KEY} does not expose issue type {JIRA_ISSUE_TYPE}"
        )
    return {
        "id": str(project.get("id", "")),
        "key": str(project.get("key", JIRA_PROJECT_KEY)),
        "name": str(project.get("name", "")),
        "issue_type_id": str(matching_type.get("id", "")),
        "issue_type_name": str(matching_type.get("name", JIRA_ISSUE_TYPE)),
    }


def _sheet_export_url() -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", ROSTER_SHEET_ID):
        raise RuntimeError("The configured roster sheet ID is invalid")
    if not ROSTER_SHEET_GID.isdigit():
        raise RuntimeError("The configured roster sheet tab ID is invalid")
    return (
        f"https://docs.google.com/spreadsheets/d/{ROSTER_SHEET_ID}/export"
        f"?format=csv&gid={ROSTER_SHEET_GID}"
    )


def _read_roster_rows() -> list[dict[str, str]]:
    if ROSTER_CSV_PATH:
        raw = Path(ROSTER_CSV_PATH).read_text(encoding="utf-8", errors="replace")
    else:
        request = Request(
            _sheet_export_url(),
            headers={"User-Agent": f"OpsPilot/{RELEASE}"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=EXTERNAL_REQUEST_TIMEOUT_SECONDS) as response:
                content_type = response.headers.get("Content-Type", "").lower()
                content = response.read(EXTERNAL_RESPONSE_LIMIT + 1)
        except (HTTPError, URLError) as error:
            raise RuntimeError(
                "Roster sheet is not readable by the service; configure a local read-only CSV sync"
            ) from error
        if len(content) > EXTERNAL_RESPONSE_LIMIT:
            raise RuntimeError("Roster sheet exceeded the safety limit")
        if "text/html" in content_type:
            raise RuntimeError(
                "Roster sheet requires authentication; configure a local read-only CSV sync"
            )
        raw = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    rows: list[dict[str, str]] = []
    for row in reader:
        normalized = {
            re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_"): _safe_text(value)
            for key, value in row.items()
            if key is not None
        }
        if any(normalized.values()):
            rows.append(normalized)
        if len(rows) >= 500:
            break
    return rows


def _on_call() -> dict[str, Any]:
    try:
        rows = _read_roster_rows()
    except (OSError, RuntimeError, ValueError) as error:
        return {"status": "unavailable", "message": str(error)}
    active_values = {"active", "yes", "true", "on_call", "primary", "current"}
    status_fields = ("on_call", "active", "status", "current_shift")
    active = next(
        (
            row
            for row in rows
            if any(row.get(field, "").casefold() in active_values for field in status_fields)
        ),
        None,
    )
    if active is None:
        return {
            "status": "unresolved",
            "message": "No row is explicitly marked active in the roster",
            "rows_seen": len(rows),
        }
    name = next(
        (
            active.get(field, "")
            for field in ("primary_engineer", "engineer", "name", "on_call_engineer")
            if active.get(field)
        ),
        "",
    )
    return {
        "status": "resolved",
        "name": name,
        "email": active.get("email", ""),
        "chat_user_id": active.get("chat_user_id", ""),
        "team": active.get("team", "Server"),
        "service": active.get("service", "Linux"),
    }


def integration_status() -> dict[str, Any]:
    jira_ready = bool(JIRA_EMAIL and JIRA_API_TOKEN)
    chat_ready = bool(CHAT_WEBHOOK_URL)
    action_ready = len(ACTION_TOKEN) >= 24
    return {
        "release": RELEASE,
        "mode": INTEGRATION_MODE if INTEGRATION_MODE in {"draft", "live"} else "draft",
        "workflow": "NOC",
        "jira": {
            "url": JIRA_URL,
            "project_key": JIRA_PROJECT_KEY,
            "requested_label": JIRA_REQUESTED_LABEL,
            "issue_type": JIRA_ISSUE_TYPE,
            "credentials_configured": jira_ready,
            "requires_validation": JIRA_PROJECT_KEY != JIRA_REQUESTED_LABEL,
        },
        "google_chat": {
            "space": GOOGLE_CHAT_SPACE,
            "webhook_configured": chat_ready,
        },
        "meet": {"url": MEET_URL, "mode": "fixed_bridge"},
        "roster": {
            "sheet_id": ROSTER_SHEET_ID,
            "sheet_gid": ROSTER_SHEET_GID,
            "source": "local_csv" if ROSTER_CSV_PATH else "google_sheet_export",
        },
        "live_ready": jira_ready and chat_ready and action_ready,
        "external_writes_enabled": INTEGRATION_MODE == "live",
    }


def validate_integrations() -> tuple[int, dict[str, Any]]:
    checks: dict[str, Any] = {}
    try:
        checks["jira"] = {"status": "validated", **_jira_project()}
    except (RuntimeError, ValueError) as error:
        checks["jira"] = {"status": "blocked", "message": str(error)}
    on_call = _on_call()
    checks["roster"] = on_call
    checks["google_chat"] = {
        "status": "configured" if CHAT_WEBHOOK_URL else "blocked",
        "space": GOOGLE_CHAT_SPACE,
        "message": (
            "Webhook is configured; no test message was posted"
            if CHAT_WEBHOOK_URL
            else "Webhook is not configured"
        ),
    }
    checks["meet"] = {"status": "configured", "url": MEET_URL}
    ready = (
        checks["jira"]["status"] == "validated"
        and checks["google_chat"]["status"] == "configured"
        and len(ACTION_TOKEN) >= 24
    )
    return (
        HTTPStatus.OK if ready else HTTPStatus.PRECONDITION_FAILED,
        {
            "status": "ready" if ready else "blocked",
            "external_write_performed": False,
            "checks": checks,
        },
    )


def _incident_priority(metric: str, requested: str) -> tuple[str, str]:
    normalized = requested.casefold()
    if "heartbeat" in metric.casefold() or normalized in {"p1", "highest", "sev-1"}:
        return "Highest", "SEV-1"
    if normalized in {"p2", "high", "sev-2"}:
        return "High", "SEV-2"
    return "Medium", "SEV-3"


def prepare_incident(payload: dict[str, Any]) -> dict[str, Any]:
    metric = _safe_text(payload.get("metric"), 160) or "Server health alert"
    priority, severity = _incident_priority(metric, _safe_text(payload.get("priority"), 32))
    snapshot = COLLECTOR.snapshot()
    host = snapshot["host"]
    on_call = _on_call()
    summary = f"[OpsPilot][{severity}] {metric} on {host['hostname']}"
    description_lines = [
        f"OpsPilot detected {metric}.",
        f"Host: {host['hostname']} ({host['ip_address']})",
        f"CPU: {snapshot['cpu']['percent']}% | Memory: {snapshot['memory']['percent']}% | "
        f"Root FS: {snapshot['disk']['percent']}% | Load: {snapshot['cpu']['load_1m']}",
        f"Health: {snapshot['health']['status']} ({snapshot['health']['score']}/100)",
        f"Meet bridge: {MEET_URL}",
        "Prepared from live read-only telemetry. Remediation requires engineer approval.",
    ]
    return {
        "status": "prepared",
        "prepared_at": iso_now(),
        "mode": integration_status()["mode"],
        "summary": summary,
        "description": "\n".join(description_lines),
        "priority": priority,
        "severity": severity,
        "host": host,
        "telemetry": {
            "cpu_percent": snapshot["cpu"]["percent"],
            "memory_percent": snapshot["memory"]["percent"],
            "disk_percent": snapshot["disk"]["percent"],
            "load_1m": snapshot["cpu"]["load_1m"],
            "health_score": snapshot["health"]["score"],
        },
        "jira": {
            "project_key": JIRA_PROJECT_KEY,
            "issue_type": JIRA_ISSUE_TYPE,
            "url": JIRA_URL,
        },
        "google_chat": {"space": GOOGLE_CHAT_SPACE},
        "meet_url": MEET_URL,
        "on_call": on_call,
        "guardrails": {
            "external_write_performed": False,
            "explicit_confirmation_required": True,
            "action_token_required": True,
        },
    }


def _adf_document(text: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": line or " "}],
            }
            for line in text.splitlines()
        ],
    }


def _create_jira_issue(draft: dict[str, Any]) -> dict[str, Any]:
    # Validate the required Jira Business Unit option before dispatch.
    if not re.fullmatch(r"customfield_[0-9]{1,30}", JIRA_BUSINESS_UNIT_FIELD_ID):
        raise RuntimeError("Jira Business Unit field is not configured")
    if not re.fullmatch(r"[0-9]{1,30}", JIRA_BUSINESS_UNIT_OPTION_ID):
        raise RuntimeError("Jira Business Unit option is not configured")
    project = _jira_project()
    _, response = _external_json(
        "POST",
        f"{JIRA_URL}/rest/api/3/issue",
        headers=_jira_headers(),
        payload={
            "fields": {
                "project": {"id": project["id"]},
                "issuetype": {"id": project["issue_type_id"]},
                "summary": draft["summary"],
                "description": _adf_document(draft["description"]),
                "priority": {"name": draft["priority"]},
                "labels": ["opspilot", "noc-automation", draft["severity"].lower()],
                # Required Jira Business Unit field.
                JIRA_BUSINESS_UNIT_FIELD_ID: (
                    [{"id": JIRA_BUSINESS_UNIT_OPTION_ID}]
                    if JIRA_BUSINESS_UNIT_MULTIPLE
                    else {"id": JIRA_BUSINESS_UNIT_OPTION_ID}
                ),
            }
        },
    )
    issue_key = str(response.get("key", ""))
    if not issue_key:
        raise RuntimeError("Jira accepted the request but did not return an issue key")
    return {"key": issue_key, "url": f"{JIRA_URL}/browse/{issue_key}"}


def _post_chat(draft: dict[str, Any], jira_issue: dict[str, Any]) -> dict[str, Any]:
    if not CHAT_WEBHOOK_URL:
        raise RuntimeError("Google Chat webhook is not configured")
    on_call = draft["on_call"]
    assignee = on_call.get("name") if on_call.get("status") == "resolved" else "Unresolved"
    chat_user_id = on_call.get("chat_user_id", "") if isinstance(on_call, dict) else ""
    mention = f" <users/{chat_user_id}>" if re.fullmatch(r"[0-9]{5,40}", chat_user_id) else ""
    message = "\n".join(
        [
            f"{draft['severity']} · {draft['summary']}",
            f"Jira: {jira_issue['url']}",
            f"Bridge: {draft['meet_url']}",
            f"On-call: {assignee}{mention}",
            f"CPU {draft['telemetry']['cpu_percent']}% · Memory {draft['telemetry']['memory_percent']}% · "
            f"Root FS {draft['telemetry']['disk_percent']}% · Load {draft['telemetry']['load_1m']}",
            "Evidence was collected read-only by OpsPilot.",
        ]
    )
    _, response = _external_json("POST", CHAT_WEBHOOK_URL, payload={"text": message})
    return {"space": GOOGLE_CHAT_SPACE, "message_name": str(response.get("name", ""))}


def run_allowed_command(command: str) -> dict[str, Any]:
    started = time.monotonic()
    if command not in ALLOWED_COMMANDS:
        return {
            "status": "blocked",
            "message": "Command is not present in the reviewed read-only allowlist",
            "command": command,
        }

    if command == "test -f /var/run/reboot-required && cat /var/run/reboot-required || echo no":
        marker = Path("/var/run/reboot-required")
        stdout = read_text(str(marker)) if marker.exists() else "no\n"
        stderr = ""
        exit_code = 0
    else:
        sort_output = command == "ps -eo state,pid,comm | sort"
        if command == "top":
            argv = ["/usr/bin/top", "-b", "-n", "1"]
        elif sort_output:
            argv = ["/usr/bin/ps", "-eo", "state,pid,comm"]
        elif command == "ulimit -a":
            argv = ["/bin/bash", "--noprofile", "--norc", "-c", "ulimit -a"]
        elif command == "ls -1 /boot/vmlinuz-*":
            argv = ["/usr/bin/ls", "-1", *sorted(glob.glob("/boot/vmlinuz-*"))]
        else:
            argv = shlex.split(command)
            executable = shutil.which(
                argv[0],
                path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            if executable is None:
                return {
                    "status": "completed",
                    "command": command,
                    "output": f"{argv[0]}: utility is not installed on this host\n",
                    "stdout": "",
                    "stderr": f"{argv[0]}: utility is not installed on this host\n",
                    "exit_code": 127,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "truncated": False,
                    "generated_at": iso_now(),
                }
            argv[0] = executable

        try:
            completed = subprocess.run(
                argv,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env={
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL": "C",
                    "LANG": "C",
                    "SYSTEMD_PAGER": "cat",
                },
            )
            stdout = completed.stdout
            stderr = completed.stderr
            if sort_output:
                stdout = "\n".join(sorted(stdout.splitlines())) + ("\n" if stdout else "")
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as error:
            partial = error.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            stdout = partial
            stderr = (
                f"[OpsPilot stopped this diagnostic after "
                f"{COMMAND_TIMEOUT_SECONDS} seconds]\n"
            )
            exit_code = 124
        except OSError as error:
            stdout = ""
            stderr = f"{type(error).__name__}: {error}\n"
            exit_code = 127

    output = stdout
    if stderr:
        output += ("\n" if output and not output.endswith("\n") else "") + stderr
    encoded = output.encode("utf-8", errors="replace")
    truncated = len(encoded) > COMMAND_OUTPUT_LIMIT
    if truncated:
        output = encoded[:COMMAND_OUTPUT_LIMIT].decode("utf-8", errors="replace")
        output += "\n[OpsPilot output limit reached: remaining output omitted]\n"

    result = {
        "status": "completed",
        "command": command,
        "output": output,
        "stdout": stdout[:COMMAND_OUTPUT_LIMIT],
        "stderr": stderr[:COMMAND_OUTPUT_LIMIT],
        "exit_code": exit_code,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "truncated": truncated,
        "generated_at": iso_now(),
    }
    print(
        "command_audit "
        f"command={json.dumps(command)} exit_code={exit_code} "
        f"duration_ms={result['duration_ms']} truncated={truncated}",
        flush=True,
    )
    return result


class LinuxCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cpu_previous = self._read_cpu_ticks()
        self._network_previous = self._read_network_totals()
        self._network_previous_time = time.monotonic()
        self._last_snapshot: dict[str, Any] | None = None
        self._last_snapshot_time = 0.0

    @staticmethod
    def _read_cpu_ticks() -> tuple[int, int]:
        fields = read_text("/proc/stat").splitlines()[0].split()[1:]
        values = [int(value) for value in fields]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return sum(values), idle

    @staticmethod
    def _read_network_totals() -> tuple[int, int]:
        received = 0
        transmitted = 0
        for line in read_text("/proc/net/dev").splitlines()[2:]:
            interface, data = line.split(":", 1)
            if interface.strip() == "lo":
                continue
            fields = data.split()
            received += int(fields[0])
            transmitted += int(fields[8])
        return received, transmitted

    @staticmethod
    def _os_release() -> dict[str, str]:
        values: dict[str, str] = {}
        try:
            for line in read_text("/etc/os-release").splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
        except OSError:
            pass
        return values

    @staticmethod
    def _primary_ip() -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 1))
            return str(sock.getsockname()[0])
        except OSError:
            try:
                addresses = socket.gethostbyname_ex(socket.gethostname())[2]
                return next((item for item in addresses if not item.startswith("127.")), "127.0.0.1")
            except OSError:
                return "127.0.0.1"
        finally:
            sock.close()

    def _cpu(self) -> dict[str, Any]:
        current_total, current_idle = self._read_cpu_ticks()
        previous_total, previous_idle = self._cpu_previous
        total_delta = max(1, current_total - previous_total)
        idle_delta = max(0, current_idle - previous_idle)
        percent = max(0.0, min(100.0, 100.0 * (1.0 - idle_delta / total_delta)))
        self._cpu_previous = (current_total, current_idle)

        frequency_mhz = 0.0
        try:
            for line in read_text("/proc/cpuinfo").splitlines():
                if line.lower().startswith("cpu mhz"):
                    frequency_mhz = float(line.split(":", 1)[1].strip())
                    break
        except (OSError, ValueError, IndexError):
            pass

        load_1m, load_5m, load_15m = os.getloadavg()
        return {
            "percent": round(percent, 1),
            "count": os.cpu_count() or 1,
            "frequency_mhz": round(frequency_mhz, 1),
            "load_1m": round(load_1m, 2),
            "load_5m": round(load_5m, 2),
            "load_15m": round(load_15m, 2),
        }

    @staticmethod
    def _memory() -> dict[str, Any]:
        data: dict[str, int] = {}
        for line in read_text("/proc/meminfo").splitlines():
            key, value = line.split(":", 1)
            data[key] = bytes_from_kib(value)

        total = data.get("MemTotal", 0)
        available = data.get("MemAvailable", data.get("MemFree", 0))
        cached = data.get("Cached", 0) + data.get("SReclaimable", 0)
        used = max(0, total - available)
        swap_used = max(0, data.get("SwapTotal", 0) - data.get("SwapFree", 0))
        percent = (used / total * 100.0) if total else 0.0
        return {
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": available,
            "cached_bytes": cached,
            "swap_total_bytes": data.get("SwapTotal", 0),
            "swap_used_bytes": swap_used,
            "percent": round(percent, 1),
        }

    @staticmethod
    def _disk() -> dict[str, Any]:
        usage = shutil.disk_usage("/")
        percent = (usage.used / usage.total * 100.0) if usage.total else 0.0
        return {
            "mount": "/",
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": round(percent, 1),
        }

    def _network(self) -> dict[str, Any]:
        received, transmitted = self._read_network_totals()
        now = time.monotonic()
        elapsed = max(0.001, now - self._network_previous_time)
        previous_received, previous_transmitted = self._network_previous
        rx_rate = max(0.0, (received - previous_received) / elapsed)
        tx_rate = max(0.0, (transmitted - previous_transmitted) / elapsed)
        self._network_previous = (received, transmitted)
        self._network_previous_time = now
        return {
            "rx_bytes": received,
            "tx_bytes": transmitted,
            "rx_bytes_per_second": round(rx_rate, 1),
            "tx_bytes_per_second": round(tx_rate, 1),
        }

    @staticmethod
    def _service(unit: str) -> dict[str, Any]:
        result = {
            "name": unit,
            "state": "unknown",
            "substate": "unknown",
            "description": "systemd unit",
            "main_pid": 0,
        }
        try:
            completed = subprocess.run(
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--no-pager",
                    "--property=ActiveState,SubState,Description,MainPID",
                    unit,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            for line in completed.stdout.splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key == "ActiveState":
                    result["state"] = value or "unknown"
                elif key == "SubState":
                    result["substate"] = value or "unknown"
                elif key == "Description":
                    result["description"] = value or "systemd unit"
                elif key == "MainPID":
                    result["main_pid"] = int(value or 0)
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        return result

    @staticmethod
    def _processes() -> list[dict[str, Any]]:
        try:
            completed = subprocess.run(
                [
                    "/usr/bin/ps",
                    "-eo",
                    "pid=,user=,comm=,pcpu=,pmem=,stat=",
                    "--sort=-pcpu",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=3,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError):
            completed = None

        rows: list[dict[str, Any]] = []
        if completed is not None:
            for line in completed.stdout.splitlines()[:MAX_PROCESS_ROWS]:
                fields = line.split(None, 5)
                if len(fields) != 6:
                    continue
                pid, user, name, cpu, memory, state = fields
                try:
                    rows.append(
                        {
                            "pid": int(pid),
                            "user": user,
                            "name": name,
                            "cpu_percent": round(float(cpu), 1),
                            "memory_percent": round(float(memory), 1),
                            "state": "Running" if state.startswith("R") else "Sleeping",
                        }
                    )
                except ValueError:
                    continue
        return rows or LinuxCollector._processes_from_proc()

    @staticmethod
    def _processes_from_proc() -> list[dict[str, Any]]:
        """Portable fallback for restricted environments where procps fails."""
        rows: list[dict[str, Any]] = []
        clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        uptime = float(read_text("/proc/uptime").split()[0])
        memory_total = 1
        for line in read_text("/proc/meminfo").splitlines():
            if line.startswith("MemTotal:"):
                memory_total = max(1, bytes_from_kib(line.split(":", 1)[1]))
                break

        for proc_path in Path("/proc").iterdir():
            if not proc_path.name.isdigit():
                continue
            try:
                stat_line = (proc_path / "stat").read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                closing_paren = stat_line.rfind(")")
                name = stat_line[stat_line.find("(") + 1:closing_paren]
                fields = stat_line[closing_paren + 2:].split()
                state_code = fields[0]
                cpu_ticks = int(fields[11]) + int(fields[12])
                start_ticks = int(fields[19])
                resident_pages = int(fields[21])
                age = max(0.001, uptime - start_ticks / clock_ticks)
                cpu_percent = min(100.0, cpu_ticks / clock_ticks / age * 100.0)
                memory_percent = resident_pages * page_size / memory_total * 100.0

                status_lines = (proc_path / "status").read_text(
                    encoding="utf-8",
                    errors="replace",
                ).splitlines()
                uid_line = next(
                    line for line in status_lines if line.startswith("Uid:")
                )
                uid = int(uid_line.split()[1])
                try:
                    user = pwd.getpwuid(uid).pw_name
                except KeyError:
                    user = str(uid)

                rows.append(
                    {
                        "pid": int(proc_path.name),
                        "user": user,
                        "name": name,
                        "cpu_percent": round(cpu_percent, 1),
                        "memory_percent": round(memory_percent, 1),
                        "state": "Running" if state_code == "R" else "Sleeping",
                    }
                )
            except (OSError, ValueError, IndexError, StopIteration):
                continue

        rows.sort(
            key=lambda item: (item["cpu_percent"], item["memory_percent"]),
            reverse=True,
        )
        return rows[:MAX_PROCESS_ROWS]

    @staticmethod
    def _sessions() -> list[dict[str, Any]]:
        """Return active login sessions without reading credential material."""
        try:
            completed = subprocess.run(
                ["/usr/bin/who", "--ips"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError):
            return []

        sessions: list[dict[str, Any]] = []
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            source = fields[-1].strip("()") if fields[-1].startswith("(") else "local"
            sessions.append(
                {
                    "user": fields[0],
                    "terminal": fields[1],
                    "login_time": " ".join(fields[2:4]),
                    "source": source,
                }
            )
        return sessions

    @staticmethod
    def _users(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Collect public account metadata from passwd/group databases only."""
        active_counts: dict[str, int] = {}
        for session in sessions:
            username = str(session.get("user", ""))
            active_counts[username] = active_counts.get(username, 0) + 1

        group_memberships: dict[str, list[str]] = {}
        for entry in grp.getgrall():
            for username in entry.gr_mem:
                group_memberships.setdefault(username, []).append(entry.gr_name)

        rows: list[dict[str, Any]] = []
        for entry in pwd.getpwall():
            groups = set(group_memberships.get(entry.pw_name, []))
            try:
                groups.add(grp.getgrgid(entry.pw_gid).gr_name)
            except KeyError:
                groups.add(str(entry.pw_gid))

            interactive = entry.pw_shell not in {
                "/usr/sbin/nologin",
                "/sbin/nologin",
                "/bin/false",
                "/usr/bin/false",
            }
            if entry.pw_uid == 0:
                account_type = "superuser"
            elif entry.pw_uid >= 1000 and interactive:
                account_type = "human"
            else:
                account_type = "service"

            rows.append(
                {
                    "username": entry.pw_name,
                    "uid": entry.pw_uid,
                    "gid": entry.pw_gid,
                    "home": entry.pw_dir,
                    "shell": entry.pw_shell,
                    "groups": sorted(groups),
                    "account_type": account_type,
                    "interactive": interactive,
                    "sudo_capable": bool(groups.intersection({"sudo", "wheel"})) or entry.pw_uid == 0,
                    "active_sessions": active_counts.get(entry.pw_name, 0),
                }
            )

        rows.sort(
            key=lambda item: (
                -int(item["active_sessions"]),
                0 if item["account_type"] == "human" else 1,
                int(item["uid"]),
            )
        )
        return rows[:MAX_USER_ROWS]

    @staticmethod
    def _mounts() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        allowed_virtual = {"/run", "/dev/shm"}
        try:
            lines = read_text("/proc/mounts").splitlines()
        except OSError:
            return rows

        for line in lines:
            fields = line.split()
            if len(fields) < 3:
                continue
            device, mount, filesystem = fields[:3]
            if mount in seen:
                continue
            if not device.startswith("/dev/") and mount not in allowed_virtual:
                continue
            try:
                usage = shutil.disk_usage(mount)
                stat = os.statvfs(mount)
            except OSError:
                continue
            seen.add(mount)
            inode_total = stat.f_files
            inode_used = max(0, inode_total - stat.f_ffree)
            rows.append(
                {
                    "device": device,
                    "mount": mount.replace("\\040", " "),
                    "filesystem": filesystem,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent": round(usage.used / usage.total * 100.0, 1) if usage.total else 0.0,
                    "inode_percent": round(inode_used / inode_total * 100.0, 1) if inode_total else 0.0,
                }
            )
        rows.sort(key=lambda item: (0 if item["mount"] == "/" else 1, item["mount"]))
        return rows[:MAX_MOUNT_ROWS]

    @staticmethod
    def _host() -> dict[str, Any]:
        uptime_seconds = float(read_text("/proc/uptime").split()[0])
        boot_epoch = time.time() - uptime_seconds
        os_release = LinuxCollector._os_release()
        timezone_name = time.tzname[0] if time.tzname else "local"
        return {
            "hostname": socket.gethostname(),
            "ip_address": LinuxCollector._primary_ip(),
            "os_name": os_release.get("PRETTY_NAME", platform.system()),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "uptime_seconds": int(uptime_seconds),
            "boot_time_local": local_datetime(boot_epoch),
            "timezone": timezone_name,
        }

    @staticmethod
    def _health(
        cpu: dict[str, Any],
        memory: dict[str, Any],
        disk: dict[str, Any],
        services: list[dict[str, Any]],
    ) -> dict[str, Any]:
        checks = [
            memory["percent"] < 90,
            disk["percent"] < 90,
            cpu["percent"] < 95,
            cpu["load_1m"] < max(2, cpu["count"] * 1.5),
            all(item["state"] == "active" for item in services),
        ]
        score = 100
        score -= sum(12 for item in services if item["state"] != "active")
        if memory["percent"] >= 85:
            score -= 8
        if disk["percent"] >= 85:
            score -= 12
        if cpu["percent"] >= 90:
            score -= 8
        score = max(0, min(100, score))
        status = "Excellent" if score >= 90 else "Stable" if score >= 75 else "Review"
        return {
            "score": score,
            "status": status,
            "critical_pass": sum(1 for item in checks if item),
            "critical_total": len(checks),
        }

    @staticmethod
    def _signals(
        services: list[dict[str, Any]],
        memory: dict[str, Any],
        disk: dict[str, Any],
    ) -> list[dict[str, str]]:
        active = sum(1 for item in services if item["state"] == "active")
        signals = [
            {
                "title": "Telemetry sample collected",
                "detail": "CPU, memory, disk, network and process probes completed",
                "age": "now",
            },
            {
                "title": f"{active}/{len(services)} core units healthy",
                "detail": "nginx, OpsPilot API and lab automation checked through systemd",
                "age": "now",
            },
        ]
        if memory["percent"] >= 80:
            signals.append(
                {
                    "title": "Memory warning threshold reached",
                    "detail": f"Memory utilization is {memory['percent']:.0f}%",
                    "age": "now",
                }
            )
        else:
            signals.append(
                {
                    "title": "Memory headroom healthy",
                    "detail": f"{100 - memory['percent']:.0f}% capacity currently available",
                    "age": "live",
                }
            )
        signals.append(
            {
                "title": "Root filesystem within policy",
                "detail": f"{100 - disk['percent']:.0f}% disk capacity remains free",
                "age": "live",
            }
        )
        return signals

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if self._last_snapshot is not None and now - self._last_snapshot_time < 1.5:
                return self._last_snapshot

            cpu = self._cpu()
            memory = self._memory()
            disk = self._disk()
            network = self._network()
            services = [self._service(unit) for unit in SERVICE_NAMES]
            sessions = self._sessions()
            health = self._health(cpu, memory, disk, services)
            snapshot = {
                "service": "opspilot-dashboard-agent",
                "release": RELEASE,
                "generated_at": iso_now(),
                "host": self._host(),
                "cpu": cpu,
                "memory": memory,
                "disk": disk,
                "network": network,
                "services": services,
                "processes": self._processes(),
                "sessions": sessions,
                "users": self._users(sessions),
                "mounts": self._mounts(),
                "signals": self._signals(services, memory, disk),
                "health": health,
                "commands": sorted(ALLOWED_COMMANDS),
            }
            self._last_snapshot = snapshot
            self._last_snapshot_time = now
            return snapshot


COLLECTOR = LinuxCollector()


class MetricStore:
    """Small persistent time-series store used by the range selector.

    A production deployment can replace this adapter with Prometheus or
    Zabbix, but the HTTP contract and strict range allowlist stay unchanged.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as database:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS metric_samples (
                    sampled_at REAL PRIMARY KEY,
                    cpu REAL NOT NULL,
                    memory REAL NOT NULL,
                    disk REAL NOT NULL,
                    load REAL NOT NULL,
                    rx REAL NOT NULL,
                    tx REAL NOT NULL
                )
                """
            )
            database.execute(
                "CREATE INDEX IF NOT EXISTS metric_samples_time "
                "ON metric_samples(sampled_at)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=3.0)

    def record(self, snapshot: dict[str, Any]) -> None:
        sampled_at = time.time()
        values = (
            sampled_at,
            float(snapshot["cpu"]["percent"]),
            float(snapshot["memory"]["percent"]),
            float(snapshot["disk"]["percent"]),
            float(snapshot["cpu"]["load_1m"]),
            float(snapshot["network"]["rx_bytes_per_second"]),
            float(snapshot["network"]["tx_bytes_per_second"]),
        )
        with self._lock, self._connect() as database:
            database.execute(
                "INSERT OR REPLACE INTO metric_samples "
                "(sampled_at,cpu,memory,disk,load,rx,tx) VALUES (?,?,?,?,?,?,?)",
                values,
            )
            database.execute(
                "DELETE FROM metric_samples WHERE sampled_at < ?",
                (sampled_at - METRIC_RETENTION_SECONDS,),
            )

    def query(self, range_key: str) -> dict[str, Any]:
        if range_key not in RANGE_CONFIG:
            raise ValueError("Unsupported metric range")
        window_seconds, step_seconds = RANGE_CONFIG[range_key]
        since = time.time() - window_seconds
        with self._lock, self._connect() as database:
            rows = database.execute(
                """
                SELECT CAST(sampled_at / ? AS INTEGER) * ? AS bucket,
                       AVG(cpu), AVG(memory), AVG(disk), AVG(load),
                       AVG(rx), AVG(tx)
                FROM metric_samples
                WHERE sampled_at >= ?
                GROUP BY bucket
                ORDER BY bucket
                """,
                (step_seconds, step_seconds, since),
            ).fetchall()
        return {
            "range": range_key,
            "window_seconds": window_seconds,
            "step_seconds": step_seconds,
            "samples": [
                {
                    "timestamp": dt.datetime.fromtimestamp(
                        row[0], dt.timezone.utc
                    ).isoformat(),
                    "cpu": round(row[1], 2),
                    "memory": round(row[2], 2),
                    "disk": round(row[3], 2),
                    "load": round(row[4], 3),
                    "rx": round(row[5], 2),
                    "tx": round(row[6], 2),
                }
                for row in rows
            ],
        }


METRIC_STORE = MetricStore(METRICS_DB_PATH)
AI_ENGINE = OpsPilotAIEngine(run_allowed_command, ALLOWED_COMMANDS)
RCA_MANAGER = AutonomousRCAManager(AI_ENGINE)


class IncidentStore:
    """Persistent idempotency ledger for externally dispatched incidents."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as database:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_dispatches (
                    idempotency_key TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=3.0)

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as database:
            row = database.execute(
                "SELECT result_json FROM incident_dispatches WHERE idempotency_key = ?",
                (key,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def record(self, key: str, result: dict[str, Any]) -> None:
        with self._lock, self._connect() as database:
            database.execute(
                "INSERT INTO incident_dispatches "
                "(idempotency_key,created_at,result_json) VALUES (?,?,?)",
                (key, iso_now(), json.dumps(result, separators=(",", ":"))),
            )


INCIDENT_STORE = IncidentStore(INTEGRATION_DB_PATH)


def dispatch_incident(
    payload: dict[str, Any],
    *,
    supplied_token: str,
    idempotency_key: str,
) -> tuple[int, dict[str, Any]]:
    if INTEGRATION_MODE != "live":
        return HTTPStatus.CONFLICT, {
            "status": "draft_only",
            "message": "External writes are disabled until integration mode is changed to live",
            "draft": prepare_incident(payload),
        }
    if len(ACTION_TOKEN) < 24 or not supplied_token or supplied_token != ACTION_TOKEN:
        return HTTPStatus.UNAUTHORIZED, {
            "status": "unauthorized",
            "message": "A valid OpsPilot action token is required",
        }
    if not payload.get("confirm") is True:
        return HTTPStatus.BAD_REQUEST, {
            "status": "confirmation_required",
            "message": "Set confirm=true only after reviewing the prepared incident",
        }
    if not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idempotency_key):
        return HTTPStatus.BAD_REQUEST, {
            "status": "error",
            "message": "A valid idempotency key is required",
        }
    existing = INCIDENT_STORE.get(idempotency_key)
    if existing is not None:
        return HTTPStatus.OK, {**existing, "idempotent_replay": True}

    draft = prepare_incident(payload)
    jira_issue = _create_jira_issue(draft)
    result: dict[str, Any] = {
        "status": "partial",
        "created_at": iso_now(),
        "jira": jira_issue,
        "meet_url": MEET_URL,
        "on_call": draft["on_call"],
        "chat": {"space": GOOGLE_CHAT_SPACE, "status": "pending"},
    }
    try:
        chat = _post_chat(draft, jira_issue)
        result["chat"] = {**chat, "status": "posted"}
        result["status"] = "completed"
    except RuntimeError as error:
        result["chat"] = {
            "space": GOOGLE_CHAT_SPACE,
            "status": "failed",
            "message": str(error),
        }
    INCIDENT_STORE.record(idempotency_key, result)
    print(
        "incident_dispatch_audit "
        f"idempotency_key={json.dumps(idempotency_key)} "
        f"jira_key={json.dumps(jira_issue['key'])} status={result['status']}",
        flush=True,
    )
    return (HTTPStatus.OK if result["status"] == "completed" else HTTPStatus.BAD_GATEWAY), result


def metric_sampler() -> None:
    while True:
        started = time.monotonic()
        try:
            snapshot = COLLECTOR.snapshot()
            METRIC_STORE.record(snapshot)
            RCA_MANAGER.observe(snapshot)
        except Exception as error:  # Keep telemetry API alive if storage fails.
            print(f"metric_store_error={type(error).__name__}: {error}", flush=True)
        elapsed = time.monotonic() - started
        time.sleep(max(0.25, METRIC_SAMPLE_SECONDS - elapsed))


class OpsPilotHandler(BaseHTTPRequestHandler):
    server_version = "OpsPilotDashboard/1.0"
    sys_version = ""

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "opspilot-dashboard-agent",
                    "release": RELEASE,
                    "time_utc": iso_now(),
                },
            )
            return
        if path == "/api/v1/dashboard":
            try:
                payload = dict(COLLECTOR.snapshot())
                payload["integrations"] = integration_status()
                payload["ai_signal"] = RCA_MANAGER.signal()
                requested_range = parse_qs(parsed.query).get("range", [None])[0]
                if requested_range is not None:
                    if requested_range not in RANGE_CONFIG:
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {
                                "status": "error",
                                "message": "range must be one of " + ", ".join(RANGE_CONFIG),
                            },
                        )
                        return
                    payload = dict(payload)
                    payload["history"] = METRIC_STORE.query(requested_range)
                self._send_json(HTTPStatus.OK, payload)
            except Exception as error:  # Last-resort boundary around procfs collection.
                self.log_error("collection failure: %s", error)
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "status": "error",
                        "service": "opspilot-dashboard-agent",
                        "message": "telemetry collection failed",
                    },
                )
            return
        if path == "/api/v1/integrations/status":
            self._send_json(HTTPStatus.OK, integration_status())
            return
        if path == "/api/v1/ai/status":
            self._send_json(HTTPStatus.OK, AI_ENGINE.status())
            return
        self._send_json(
            HTTPStatus.NOT_FOUND,
            {"status": "not_found", "message": "Unknown OpsPilot dashboard endpoint"},
        )

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        allowed_paths = {
            "/api/v1/dashboard",
            "/api/v1/commands/execute",
            "/api/v1/integrations/validate",
            "/api/v1/incidents/prepare",
            "/api/v1/incidents/dispatch",
            "/api/v1/ai/query",
            "/api/v1/ai/remediations/prepare",
            "/api/v1/ai/remediations/execute",
        }
        if path not in allowed_paths:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"status": "not_found", "message": "Unknown OpsPilot dashboard endpoint"},
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        maximum_length = 4096 if path in {
            "/api/v1/dashboard",
            "/api/v1/commands/execute",
            "/api/v1/ai/remediations/prepare",
            "/api/v1/ai/remediations/execute",
        } else 16384
        if length <= 0 or length > maximum_length:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "Invalid request size"},
            )
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "Request body must be valid JSON"},
            )
            return

        if not isinstance(payload, dict):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "Request body must be a JSON object"},
            )
            return

        action = payload.get("action") if path == "/api/v1/dashboard" else None

        if path == "/api/v1/integrations/validate" or action == "validate_integrations":
            status, result = validate_integrations()
            self._send_json(status, result)
            return

        if path == "/api/v1/incidents/prepare" or action == "prepare_incident":
            self._send_json(HTTPStatus.OK, prepare_incident(payload))
            return

        if path == "/api/v1/incidents/dispatch" or action == "dispatch_incident":
            try:
                status, result = dispatch_incident(
                    payload,
                    supplied_token=self.headers.get("X-OpsPilot-Action-Token", ""),
                    idempotency_key=self.headers.get("Idempotency-Key", ""),
                )
            except (RuntimeError, ValueError, OSError, sqlite3.Error) as error:
                self.log_error("incident dispatch failure: %s", error)
                self._send_json(
                    HTTPStatus.BAD_GATEWAY,
                    {"status": "error", "message": str(error)},
                )
                return
            self._send_json(status, result)
            return

        if path == "/api/v1/ai/query" or action == "ai_query":
            question = payload.get("question")
            spike_timestamp = payload.get("spike_timestamp")
            if not isinstance(question, str) or not question.strip() or len(question) > 1000:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": "question must be between 1 and 1000 characters"},
                )
                return
            if spike_timestamp is not None and (
                not isinstance(spike_timestamp, str) or len(spike_timestamp) > 80
            ):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": "spike_timestamp must be an RFC3339 string"},
                )
                return
            try:
                result = AI_ENGINE.answer_question(
                    question.strip(),
                    COLLECTOR.snapshot(),
                    forecasts=RCA_MANAGER.forecasts(),
                    spike_timestamp=spike_timestamp,
                )
            except Exception as error:
                self.log_error("AI query failure: %s", error)
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "message": "OpsPilot could not complete the evidence analysis"},
                )
                return
            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/ai/remediations/prepare" or action == "prepare_remediation":
            action_id = payload.get("action_id")
            if not isinstance(action_id, str) or len(action_id) > 80:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": "A valid action_id is required"},
                )
                return
            try:
                result = AI_ENGINE.prepare_remediation(action_id)
            except ValueError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(error)})
                return
            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/ai/remediations/execute" or action == "execute_remediation":
            if self.headers.get("X-OpsPilot-Action", "") != "confirmed-remediation":
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"status": "blocked", "message": "The remediation action header is required"},
                )
                return
            status, result = AI_ENGINE.execute_remediation(
                action_id=str(payload.get("action_id", "")),
                approval_id=str(payload.get("approval_id", "")),
                exact_command=str(payload.get("exact_command", "")),
                confirmed=payload.get("confirm") is True,
            )
            self._send_json(status, result)
            return

        command = payload.get("command") if isinstance(payload, dict) else None
        if not isinstance(command, str) or len(command) > 300:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "A valid command string is required"},
            )
            return

        result = run_allowed_command(command)
        status = HTTPStatus.OK if result["status"] == "completed" else HTTPStatus.FORBIDDEN
        self._send_json(status, result)

    def do_HEAD(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        status = (
            HTTPStatus.OK
            if path in {
                "/healthz",
                "/api/v1/dashboard",
                "/api/v1/integrations/status",
                "/api/v1/ai/status",
            }
            else HTTPStatus.NOT_FOUND
        )
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def log_message(self, message_format: str, *args: Any) -> None:
        message = message_format % args
        print(f"{self.address_string()} {message}", flush=True)


def main() -> None:
    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        current_user = str(os.getuid())
    print(
        f"Starting OpsPilot dashboard agent {RELEASE} as {current_user} "
        f"on {LISTEN_ADDRESS}:{LISTEN_PORT}",
        flush=True,
    )
    try:
        RCA_MANAGER.seed(METRIC_STORE.query("24h")["samples"])
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"ai_forecast_seed_error={type(error).__name__}: {error}", flush=True)
    sampler = threading.Thread(
        target=metric_sampler,
        name="opspilot-metric-sampler",
        daemon=True,
    )
    sampler.start()
    server = ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), OpsPilotHandler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
