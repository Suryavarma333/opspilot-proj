"""Transactional temporal ledger, job queue, idempotency, and flapping analysis."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import (
    AlertEvent,
    AlertKind,
    AlertState,
    FlapAssessment,
    HistoricalEvent,
    IncidentStatus,
    RootCauseAnalysis,
    RootCauseClass,
    TemporalContext,
    utc_now,
)
from .security import canonical_json, evidence_hash

SCHEMA_VERSION = 2
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    alert_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    node TEXT NOT NULL,
    resource TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    metric TEXT NOT NULL,
    severity TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    current_state TEXT NOT NULL,
    status TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    threshold_json TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    annotations_json TEXT NOT NULL,
    evidence_sha256 TEXT,
    rca_json TEXT,
    jira_issue_key TEXT,
    jira_issue_url TEXT,
    slack_delivered INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_node_time
    ON incidents(node, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_resource_time
    ON incidents(resource_key, first_seen DESC);

CREATE TABLE IF NOT EXISTS transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES incidents(alert_id) ON DELETE CASCADE,
    node TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    state TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    observed_json TEXT NOT NULL,
    threshold_json TEXT NOT NULL,
    UNIQUE(alert_id, state, occurred_at)
);

CREATE INDEX IF NOT EXISTS idx_transitions_resource_time
    ON transitions(resource_key, occurred_at);
CREATE INDEX IF NOT EXISTS idx_transitions_node_time
    ON transitions(node, occurred_at);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES incidents(alert_id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    UNIQUE(alert_id, evidence_type, sha256)
);

CREATE TABLE IF NOT EXISTS llm_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES incidents(alert_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    route TEXT,
    prompt_version TEXT NOT NULL,
    prompt_sha256 TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    response_sha256 TEXT,
    latency_ms INTEGER NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES incidents(alert_id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    phase TEXT NOT NULL,
    state TEXT NOT NULL,
    external_id TEXT,
    response_sha256 TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(alert_id, destination, phase)
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key TEXT NOT NULL UNIQUE,
    alert_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_until TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_claim
    ON jobs(state, available_at, lease_until, id);

CREATE TABLE IF NOT EXISTS remediation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES incidents(alert_id) ON DELETE CASCADE,
    runbook_id TEXT NOT NULL,
    change_ticket TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    status TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    result_json TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(alert_id, runbook_id, change_ticket)
);

CREATE TABLE IF NOT EXISTS interface_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    interface_name TEXT NOT NULL,
    admin_status TEXT NOT NULL,
    oper_status TEXT NOT NULL,
    counters_json TEXT NOT NULL,
    sample_sha256 TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    UNIQUE(device_id, interface_name, collected_at)
);

CREATE INDEX IF NOT EXISTS idx_interface_samples_latest
    ON interface_samples(device_id, interface_name, collected_at DESC);

CREATE TABLE IF NOT EXISTS network_devices (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL COLLATE NOCASE UNIQUE,
    device_name TEXT NOT NULL,
    snmp_version TEXT NOT NULL CHECK(snmp_version IN ('v2c', 'v3')),
    snmp_port INTEGER NOT NULL DEFAULT 161 CHECK(snmp_port BETWEEN 1 AND 65535),
    snmp_security_level TEXT NOT NULL
        CHECK(snmp_security_level IN ('community', 'noAuthNoPriv', 'authNoPriv', 'authPriv')),
    credentials_encrypted BLOB NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(status IN ('UNKNOWN', 'UP', 'DOWN')),
    ping_latency_ms REAL,
    snmp_status TEXT NOT NULL DEFAULT 'UNKNOWN'
        CHECK(snmp_status IN ('UNKNOWN', 'UP', 'DOWN')),
    sys_name TEXT,
    sys_description TEXT,
    sys_object_id TEXT,
    uptime_seconds INTEGER,
    interface_total INTEGER,
    interface_up INTEGER,
    interface_down INTEGER,
    interface_unknown INTEGER,
    last_polled_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_devices_poll
    ON network_devices(enabled, hostname);
CREATE INDEX IF NOT EXISTS idx_network_devices_status
    ON network_devices(status, snmp_status);
"""


def _iso(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(UTC).isoformat(timespec="microseconds")


def _json(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


class LedgerError(RuntimeError):
    pass


class IncidentLedger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialization_lock = threading.Lock()
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def initialize(self) -> None:
        with self._initialization_lock:
            if self._initialized:
                return
            connection = self._connect()
            try:
                connection.executescript(SCHEMA)
                row = connection.execute(
                    "SELECT MAX(version) AS version FROM schema_meta"
                ).fetchone()
                version = int(row["version"] or 0)
                if version > SCHEMA_VERSION:
                    raise LedgerError(
                        f"database schema {version} is newer than supported {SCHEMA_VERSION}"
                    )
                if version < SCHEMA_VERSION:
                    connection.execute(
                        "INSERT INTO schema_meta(version, applied_at) VALUES (?, ?)",
                        (SCHEMA_VERSION, _iso()),
                    )
                with suppress(OSError):
                    os.chmod(self.path, 0o640)
                self._initialized = True
            finally:
                connection.close()

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        self.initialize()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def register_alert(self, alert: AlertEvent) -> tuple[bool, int | None]:
        """Persist a transition and enqueue exactly one job for this occurrence."""

        now = _iso()
        fingerprint = evidence_hash(
            {
                "kind": alert.kind,
                "node": alert.node,
                "resource": alert.resource,
                "metric": alert.metric,
            }
        )
        dedupe_key = evidence_hash(
            {
                "alert_id": alert.alert_id,
                "state": alert.state,
                "occurred_at": alert.occurred_at.isoformat(),
            }
        )
        payload = alert.model_dump(mode="json")
        with self.transaction() as connection:
            inserted = (
                connection.execute(
                    """
                    INSERT OR IGNORE INTO incidents(
                        alert_id, fingerprint, kind, source, node, resource, resource_key,
                        metric, severity, first_seen, last_seen, current_state, status,
                        observed_json, threshold_json, labels_json, annotations_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        fingerprint,
                        alert.kind.value,
                        alert.source,
                        alert.node,
                        alert.resource,
                        alert.resource_key,
                        alert.metric,
                        alert.severity,
                        _iso(alert.occurred_at),
                        _iso(alert.occurred_at),
                        alert.state.value,
                        (
                            IncidentStatus.QUEUED.value
                            if alert.state == AlertState.FIRING
                            else IncidentStatus.RESOLVED.value
                        ),
                        _json(alert.observed_value),
                        _json(alert.threshold),
                        _json(alert.labels),
                        _json(alert.annotations),
                        now,
                        now,
                    ),
                ).rowcount
                == 1
            )
            connection.execute(
                """
                UPDATE incidents
                   SET last_seen=?, current_state=?, observed_json=?, threshold_json=?,
                       status=CASE WHEN ?='resolved' THEN 'resolved' ELSE status END,
                       updated_at=?
                 WHERE alert_id=?
                """,
                (
                    _iso(alert.occurred_at),
                    alert.state.value,
                    _json(alert.observed_value),
                    _json(alert.threshold),
                    alert.state.value,
                    now,
                    alert.alert_id,
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO transitions(
                    alert_id, node, resource_key, state, occurred_at,
                    observed_json, threshold_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.node,
                    alert.resource_key,
                    alert.state.value,
                    _iso(alert.occurred_at),
                    _json(alert.observed_value),
                    _json(alert.threshold),
                ),
            )
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO jobs(
                    dedupe_key, alert_id, payload_json, state, available_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 'queued', ?, ?, ?)
                """,
                (dedupe_key, alert.alert_id, _json(payload), now, now, now),
            )
            job_id = int(cursor.lastrowid or 0) if cursor.rowcount == 1 else None
        return inserted, job_id

    def claim_job(self, worker_id: str, lease_seconds: int) -> dict[str, Any] | None:
        now = utc_now()
        lease_until = now + timedelta(seconds=lease_seconds)
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM jobs
                 WHERE available_at <= ?
                   AND (
                       state='queued'
                       OR (state='processing' AND lease_until < ?)
                   )
                 ORDER BY id
                 LIMIT 1
                """,
                (_iso(now), _iso(now)),
            ).fetchone()
            if row is None:
                return None
            changed = connection.execute(
                """
                UPDATE jobs
                   SET state='processing', attempts=attempts+1, lease_owner=?,
                       lease_until=?, updated_at=?
                 WHERE id=? AND (
                    state='queued' OR (state='processing' AND lease_until < ?)
                 )
                """,
                (worker_id, _iso(lease_until), _iso(now), row["id"], _iso(now)),
            ).rowcount
            if changed != 1:
                return None
            result = dict(row)
            result["payload"] = json.loads(result.pop("payload_json"))
            return result

    def finish_job(
        self,
        job_id: int,
        worker_id: str,
        *,
        success: bool,
        error: str | None = None,
        retry_delay_seconds: int | None = None,
    ) -> None:
        now = utc_now()
        state = "done" if success else ("queued" if retry_delay_seconds is not None else "failed")
        available = now + timedelta(seconds=retry_delay_seconds or 0)
        with self.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE jobs
                   SET state=?, available_at=?, lease_owner=NULL, lease_until=NULL,
                       last_error=?, updated_at=?
                 WHERE id=? AND lease_owner=? AND state='processing'
                """,
                (state, _iso(available), error, _iso(now), job_id, worker_id),
            ).rowcount
            if changed != 1:
                raise LedgerError("job lease is no longer owned by this worker")

    def claim_incident(self, alert_id: str) -> tuple[bool, sqlite3.Row | None]:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE alert_id=?", (alert_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"unknown incident {alert_id}")
            if row["status"] in {IncidentStatus.COMPLETE.value, IncidentStatus.RESOLVED.value}:
                return False, row
            if row["status"] == IncidentStatus.PROCESSING.value:
                return False, row
            connection.execute(
                """
                UPDATE incidents
                   SET status='processing', attempt_count=attempt_count+1,
                       last_error=NULL, updated_at=?
                 WHERE alert_id=?
                """,
                (_iso(), alert_id),
            )
            return True, row

    def save_evidence(
        self,
        alert_id: str,
        evidence_type: str,
        payload: dict[str, Any],
        sha256: str,
        collected_at: datetime,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO evidence(
                    alert_id, evidence_type, sha256, payload_json, collected_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (alert_id, evidence_type, sha256, _json(payload), _iso(collected_at)),
            )
            connection.execute(
                "UPDATE incidents SET evidence_sha256=?, updated_at=? WHERE alert_id=?",
                (sha256, _iso(), alert_id),
            )

    def complete_incident(
        self,
        alert_id: str,
        *,
        rca: RootCauseAnalysis,
        evidence_sha256: str,
        jira_issue_key: str | None,
        jira_issue_url: str | None,
        slack_delivered: bool,
        errors: list[str] | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE incidents
                   SET status='complete', rca_json=?, evidence_sha256=?,
                       jira_issue_key=COALESCE(?, jira_issue_key),
                       jira_issue_url=COALESCE(?, jira_issue_url),
                       slack_delivered=?, last_error=?, updated_at=?
                 WHERE alert_id=?
                """,
                (
                    rca.model_dump_json(),
                    evidence_sha256,
                    jira_issue_key,
                    jira_issue_url,
                    int(slack_delivered),
                    "\n".join(errors or [])[:4000] or None,
                    _iso(),
                    alert_id,
                ),
            )

    def fail_incident(self, alert_id: str, error: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE incidents SET status='failed', last_error=?, updated_at=? WHERE alert_id=?",
                (error[:4000], _iso(), alert_id),
            )

    def get_incident(self, alert_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE alert_id=?", (alert_id,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        for field in (
            "observed_json",
            "threshold_json",
            "labels_json",
            "annotations_json",
            "rca_json",
        ):
            if result.get(field) is not None:
                result[field.removesuffix("_json")] = json.loads(result.pop(field))
        return result

    def reserve_delivery(self, alert_id: str, destination: str, phase: str) -> bool:
        now = _iso()
        with self.transaction() as connection:
            existing = connection.execute(
                """
                SELECT state FROM deliveries
                 WHERE alert_id=? AND destination=? AND phase=?
                """,
                (alert_id, destination, phase),
            ).fetchone()
            if existing and existing["state"] in {"reserved", "sent", "unknown"}:
                return False
            if existing:
                connection.execute(
                    """
                    UPDATE deliveries SET state='reserved', error=NULL, updated_at=?
                     WHERE alert_id=? AND destination=? AND phase=?
                    """,
                    (now, alert_id, destination, phase),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO deliveries(
                        alert_id, destination, phase, state, created_at, updated_at
                    ) VALUES (?, ?, ?, 'reserved', ?, ?)
                    """,
                    (alert_id, destination, phase, now, now),
                )
            return True

    def finish_delivery(
        self,
        alert_id: str,
        destination: str,
        phase: str,
        *,
        state: str,
        external_id: str | None = None,
        response_sha256: str | None = None,
        error: str | None = None,
    ) -> None:
        if state not in {"sent", "failed", "unknown"}:
            raise ValueError("invalid delivery state")
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE deliveries
                   SET state=?, external_id=?, response_sha256=?, error=?, updated_at=?
                 WHERE alert_id=? AND destination=? AND phase=?
                """,
                (
                    state,
                    external_id,
                    response_sha256,
                    error,
                    _iso(),
                    alert_id,
                    destination,
                    phase,
                ),
            )

    def record_llm_run(
        self,
        *,
        alert_id: str,
        provider: str,
        model: str,
        route: str | None,
        prompt_version: str,
        prompt_sha256: str,
        evidence_sha256: str,
        response_sha256: str | None,
        latency_ms: int,
        status: str,
        error: str | None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO llm_runs(
                    alert_id, provider, model, route, prompt_version, prompt_sha256,
                    evidence_sha256, response_sha256, latency_ms, status, error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    provider,
                    model,
                    route,
                    prompt_version,
                    prompt_sha256,
                    evidence_sha256,
                    response_sha256,
                    latency_ms,
                    status,
                    error,
                    _iso(),
                ),
            )

    def flap_assessment(
        self,
        resource_key: str,
        *,
        window_days: int = 7,
        threshold_cycles: int = 5,
        now: datetime | None = None,
    ) -> FlapAssessment:
        cutoff = (now or utc_now()) - timedelta(days=window_days)
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT state, occurred_at FROM transitions
                 WHERE resource_key=? AND occurred_at>=?
                 ORDER BY occurred_at, id
                """,
                (resource_key, _iso(cutoff)),
            ).fetchall()
        states = [str(row["state"]) for row in rows]
        firing_count = states.count(AlertState.FIRING.value)
        resolved_count = states.count(AlertState.RESOLVED.value)
        state_changes = sum(
            1 for left, right in zip(states, states[1:], strict=False) if left != right
        )
        complete_cycles = 0
        armed = False
        for state in states:
            if state == AlertState.FIRING.value:
                armed = True
            elif state == AlertState.RESOLVED.value and armed:
                complete_cycles += 1
                armed = False
        return FlapAssessment(
            resource_key=resource_key,
            window_days=window_days,
            firing_count=firing_count,
            resolved_count=resolved_count,
            complete_cycles=complete_cycles,
            state_changes=state_changes,
            first_seen=(datetime.fromisoformat(rows[0]["occurred_at"]) if rows else None),
            last_seen=(datetime.fromisoformat(rows[-1]["occurred_at"]) if rows else None),
            is_flapping=complete_cycles >= threshold_cycles,
            threshold_cycles=threshold_cycles,
        )

    def temporal_context(
        self,
        alert: AlertEvent,
        *,
        window_days: int = 30,
        flapping_window_days: int = 7,
        threshold_cycles: int = 5,
        limit: int = 100,
        now: datetime | None = None,
    ) -> TemporalContext:
        cutoff = (now or utc_now()) - timedelta(days=window_days)
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT i.alert_id, i.kind, t.state, t.resource_key, t.occurred_at,
                       t.observed_json, t.threshold_json, i.severity,
                       i.rca_json, i.evidence_sha256
                  FROM transitions t
                  JOIN incidents i ON i.alert_id=t.alert_id
                 WHERE t.node=? AND t.occurred_at>=?
                 ORDER BY t.occurred_at DESC, t.id DESC
                 LIMIT ?
                """,
                (alert.node, _iso(cutoff), limit),
            ).fetchall()
        events: list[HistoricalEvent] = []
        classifications: dict[str, int] = {}
        for row in rows:
            root_class: RootCauseClass | None = None
            if row["rca_json"]:
                try:
                    parsed = json.loads(row["rca_json"])
                    root_class = RootCauseClass(parsed["summary"]["classification"])
                    classifications[root_class.value] = classifications.get(root_class.value, 0) + 1
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    root_class = None
            events.append(
                HistoricalEvent(
                    alert_id=row["alert_id"],
                    kind=AlertKind(row["kind"]),
                    state=AlertState(row["state"]),
                    resource_key=row["resource_key"],
                    occurred_at=datetime.fromisoformat(row["occurred_at"]),
                    observed_value=json.loads(row["observed_json"]),
                    threshold=json.loads(row["threshold_json"]),
                    severity=row["severity"],
                    root_cause_class=root_class,
                    evidence_sha256=row["evidence_sha256"],
                )
            )
        return TemporalContext(
            node=alert.node,
            window_days=window_days,
            event_count=len(events),
            same_resource=self.flap_assessment(
                alert.resource_key,
                window_days=flapping_window_days,
                threshold_cycles=threshold_cycles,
                now=now,
            ),
            events=events,
            recurring_classifications=classifications,
        )

    def history_for_llm(self, context: TemporalContext, *, max_chars: int = 24_000) -> str:
        body = context.model_dump_json(indent=2)
        if len(body) <= max_chars:
            return body
        compact = context.model_copy(update={"events": context.events[:25]})
        body = compact.model_dump_json(indent=2)
        return body[:max_chars]

    def import_legacy_json(self, path: Path) -> dict[str, int]:
        """One-way, idempotent importer for older `incidents.json` ledgers."""

        raw = json.loads(path.read_text(encoding="utf-8"))
        source_events = raw.get("events", raw)
        iterable: Iterable[tuple[str, Any]]
        if isinstance(source_events, dict):
            iterable = source_events.items()
        elif isinstance(source_events, list):
            iterable = ((str(index), item) for index, item in enumerate(source_events))
        else:
            raise LedgerError("legacy ledger must contain an object or list of events")

        imported = skipped = 0
        for legacy_id, item in iterable:
            if not isinstance(item, dict):
                skipped += 1
                continue
            try:
                occurred = datetime.fromisoformat(
                    str(item.get("detected_at") or item.get("created_at") or _iso())
                )
                if occurred.tzinfo is None:
                    occurred = occurred.replace(tzinfo=UTC)
                kind_value = str(item.get("kind") or "server_cpu").lower()
                kind = (
                    AlertKind(kind_value)
                    if kind_value in AlertKind._value2member_map_
                    else AlertKind.SERVER_CPU
                )
                alert = AlertEvent(
                    alert_id=str(item.get("event_id") or legacy_id).replace(" ", "-")[:128],
                    kind=kind,
                    state=(
                        AlertState.RESOLVED
                        if str(item.get("state") or item.get("status")).lower() == "resolved"
                        else AlertState.FIRING
                    ),
                    source="legacy-json",
                    node=str(item.get("hostname") or item.get("node") or socket.gethostname()),
                    resource=str(item.get("resource") or item.get("hostname") or "host"),
                    metric=str(item.get("metric") or kind.value),
                    severity=str(item.get("severity") or "SEV-2"),  # type: ignore[arg-type]
                    observed_value=item.get("observed_value", "unknown"),
                    threshold=item.get("threshold", "unknown"),
                    occurred_at=occurred,
                )
                was_new, _ = self.register_alert(alert)
                imported += int(was_new)
                skipped += int(not was_new)
            except (ValueError, TypeError, KeyError):
                skipped += 1
        return {"imported": imported, "skipped": skipped}

    def begin_remediation(
        self,
        alert_id: str,
        runbook_id: str,
        change_ticket: str,
        approved_by: str,
        request_payload: dict[str, Any],
    ) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO remediation_runs(
                    alert_id, runbook_id, change_ticket, approved_by, status,
                    request_sha256, started_at
                ) VALUES (?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    alert_id,
                    runbook_id,
                    change_ticket,
                    approved_by,
                    evidence_hash(request_payload),
                    _iso(),
                ),
            )
            return cursor.rowcount == 1

    def finish_remediation(
        self,
        alert_id: str,
        runbook_id: str,
        change_ticket: str,
        status: str,
        result: dict[str, Any],
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE remediation_runs
                   SET status=?, result_json=?, completed_at=?
                 WHERE alert_id=? AND runbook_id=? AND change_ticket=?
                """,
                (status, _json(result), _iso(), alert_id, runbook_id, change_ticket),
            )

    def latest_interface_sample(self, device_id: str, interface_name: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM interface_samples
                 WHERE device_id=? AND interface_name=?
                 ORDER BY collected_at DESC, id DESC
                 LIMIT 1
                """,
                (device_id, interface_name),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["counters"] = json.loads(result.pop("counters_json"))
        return result

    def record_interface_sample(
        self,
        *,
        device_id: str,
        interface_name: str,
        admin_status: str,
        oper_status: str,
        counters: dict[str, Any],
        sample_sha256: str,
        collected_at: datetime,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO interface_samples(
                    device_id, interface_name, admin_status, oper_status,
                    counters_json, sample_sha256, collected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    interface_name,
                    admin_status,
                    oper_status,
                    _json(counters),
                    sample_sha256,
                    _iso(collected_at),
                ),
            )

    @staticmethod
    def worker_id() -> str:
        return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
