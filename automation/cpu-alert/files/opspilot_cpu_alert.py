#!/usr/bin/env python3
"""Sustained CPU alert controller for OpsPilot v0.9.0.

The controller reads CPU utilization locally, applies consecutive-sample
thresholds, and calls the existing loopback-only OpsPilot dispatch endpoint.
Jira credentials and webhook URLs remain owned by the dashboard agent.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


INTEGRATIONS_PATH = Path("/etc/opspilot-dashboard/integrations.env")
STATE_PATH = Path("/var/lib/opspilot-cpu-alert/state.json")
LOCK_PATH = Path("/var/lib/opspilot-cpu-alert/controller.lock")
DISPATCH_URL = "http://127.0.0.1:3100/api/v1/incidents/dispatch"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError as error:
        raise SystemExit(f"Invalid {name}: {error}") from error


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError as error:
        raise SystemExit(f"Invalid {name}: {error}") from error


HIGH_THRESHOLD = env_float("OPSPILOT_CPU_HIGH_THRESHOLD", 90.0)
RECOVERY_THRESHOLD = env_float("OPSPILOT_CPU_RECOVERY_THRESHOLD", 80.0)
HIGH_SAMPLES = env_int("OPSPILOT_CPU_HIGH_SAMPLES", 4)
RECOVERY_SAMPLES = env_int("OPSPILOT_CPU_RECOVERY_SAMPLES", 3)
SAMPLE_INTERVAL_SECONDS = env_float("OPSPILOT_CPU_SAMPLE_INTERVAL_SECONDS", 1.0)


def validate_settings() -> None:
    if not 1 <= RECOVERY_THRESHOLD < HIGH_THRESHOLD <= 100:
        raise SystemExit("CPU thresholds must satisfy 1 <= recovery < high <= 100")
    if not 1 <= HIGH_SAMPLES <= 30 or not 1 <= RECOVERY_SAMPLES <= 30:
        raise SystemExit("Consecutive-sample counts must be between 1 and 30")
    if not 0.2 <= SAMPLE_INTERVAL_SECONDS <= 10:
        raise SystemExit("CPU sample interval must be between 0.2 and 10 seconds")


def read_proc_cpu() -> tuple[int, int]:
    first_line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
    fields = [int(value) for value in first_line.split()[1:]]
    if len(fields) < 4:
        raise RuntimeError("/proc/stat did not contain enough CPU counters")
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return sum(fields), idle


def calculate_cpu_percent(before: tuple[int, int], after: tuple[int, int]) -> float:
    total_delta = after[0] - before[0]
    idle_delta = after[1] - before[1]
    if total_delta <= 0:
        raise RuntimeError("CPU counters did not advance")
    busy_delta = max(0, total_delta - idle_delta)
    return round(min(100.0, busy_delta * 100.0 / total_delta), 1)


def sample_cpu() -> float:
    before = read_proc_cpu()
    time.sleep(SAMPLE_INTERVAL_SECONDS)
    after = read_proc_cpu()
    return calculate_cpu_percent(before, after)


def initial_state() -> dict[str, Any]:
    return {
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


def load_state(path: Path = STATE_PATH) -> dict[str, Any]:
    state = initial_state()
    if not path.exists():
        return state
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unable to read controller state: {error}") from error
    if not isinstance(stored, dict):
        raise RuntimeError("Controller state must be a JSON object")
    state.update(stored)
    return state


def save_state(state: dict[str, Any], path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".state.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def advance_state(
    state: dict[str, Any],
    cpu_percent: float,
    *,
    high_threshold: float = HIGH_THRESHOLD,
    recovery_threshold: float = RECOVERY_THRESHOLD,
    high_samples: int = HIGH_SAMPLES,
    recovery_samples: int = RECOVERY_SAMPLES,
) -> str:
    """Advance hysteresis state and return none, dispatch, or recovered."""
    state["last_cpu_percent"] = cpu_percent
    state["last_sample_at"] = utc_now()

    if cpu_percent >= high_threshold:
        state["high_streak"] = min(high_samples, int(state.get("high_streak", 0)) + 1)
        state["low_streak"] = 0
    elif cpu_percent < recovery_threshold:
        state["low_streak"] = min(recovery_samples, int(state.get("low_streak", 0)) + 1)
        state["high_streak"] = 0
    else:
        state["high_streak"] = 0
        state["low_streak"] = 0

    if bool(state.get("incident_open")) and state["low_streak"] >= recovery_samples:
        replacement = initial_state()
        replacement["last_cpu_percent"] = cpu_percent
        replacement["last_sample_at"] = state["last_sample_at"]
        state.clear()
        state.update(replacement)
        return "recovered"

    if not bool(state.get("incident_open")) and state["high_streak"] >= high_samples:
        if not state.get("idempotency_key"):
            state["idempotency_key"] = "cpu-alert-" + uuid.uuid4().hex
        return "dispatch"

    return "none"


def read_integrations(path: Path = INTEGRATIONS_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def dispatch(state: dict[str, Any], cpu_percent: float) -> tuple[int, dict[str, Any]]:
    config = read_integrations()
    if config.get("OPSPILOT_INTEGRATION_MODE", "draft").strip().lower() != "live":
        return 409, {
            "status": "draft_only",
            "message": "Automatic external writes are not enabled",
        }

    action_token = config.get("OPSPILOT_ACTION_TOKEN", "")
    if len(action_token) < 24:
        raise RuntimeError("OpsPilot action token is missing or invalid")

    approximate_seconds = max(1, (HIGH_SAMPLES - 1) * 20)
    payload = json.dumps(
        {
            "metric": (
                f"High CPU utilization ({cpu_percent:.1f}%) sustained for "
                f"approximately {approximate_seconds} seconds"
            ),
            "priority": "P2",
            "confirm": True,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        DISPATCH_URL,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-OpsPilot-Action-Token": action_token,
            "Idempotency-Key": str(state["idempotency_key"]),
        },
    )

    try:
        with urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            status = response.status
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        status = error.code
    except URLError as error:
        raise RuntimeError(f"OpsPilot dispatch endpoint is unavailable: {error.reason}") from error

    try:
        result = json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"OpsPilot returned invalid JSON (HTTP {status})") from error
    if not isinstance(result, dict):
        raise RuntimeError("OpsPilot dispatch response must be a JSON object")
    return status, result


def main() -> int:
    validate_settings()
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        state = load_state()
        cpu_percent = sample_cpu()
        event = advance_state(state, cpu_percent)
        save_state(state)

        print(
            f"cpu_alert_sample cpu={cpu_percent:.1f} high_streak={state['high_streak']} "
            f"low_streak={state['low_streak']} incident_open={str(state['incident_open']).lower()}"
        )

        if event == "recovered":
            print(
                f"cpu_alert_recovered cpu={cpu_percent:.1f} threshold={RECOVERY_THRESHOLD:.1f}"
            )
            save_state(state)
            return 0

        if event != "dispatch":
            return 0

        try:
            http_status, result = dispatch(state, cpu_percent)
        except (OSError, RuntimeError, ValueError) as error:
            state["last_error"] = str(error)
            save_state(state)
            print(f"cpu_alert_dispatch_failed error={json.dumps(str(error))}")
            return 1

        jira = result.get("jira") if isinstance(result.get("jira"), dict) else {}
        jira_key = str(jira.get("key", ""))
        if jira_key:
            state["incident_open"] = True
            state["jira_key"] = jira_key
            state["last_dispatch_at"] = utc_now()
            state["last_error"] = ""
            save_state(state)
            chat = result.get("chat") if isinstance(result.get("chat"), dict) else {}
            print(
                f"cpu_alert_dispatched jira_key={json.dumps(jira_key)} "
                f"chat_status={json.dumps(str(chat.get('status', 'unknown')))} "
                f"http_status={http_status}"
            )
            return 0

        state["last_error"] = str(result.get("message", f"HTTP {http_status}"))
        save_state(state)
        print(
            f"cpu_alert_not_dispatched status={json.dumps(str(result.get('status', 'error')))} "
            f"http_status={http_status}"
        )
        return 0 if result.get("status") == "draft_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
