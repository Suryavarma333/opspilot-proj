from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from opspilot_enterprise.ledger import IncidentLedger
from opspilot_enterprise.llm import deterministic_fallback
from opspilot_enterprise.models import (
    CommandEvidence,
    RemediationRequest,
    TemporalContext,
)
from opspilot_enterprise.remediation import RemediationDenied, RemediationEngine
from opspilot_enterprise.security import approval_token


def completed_ledger(tmp_path: Path, cpu_alert, empty_history: TemporalContext) -> IncidentLedger:
    ledger = IncidentLedger(tmp_path / "remediation.sqlite3")
    ledger.register_alert(cpu_alert)
    claimed, _ = ledger.claim_incident(cpu_alert.alert_id)
    assert claimed
    rca = deterministic_fallback(cpu_alert, empty_history, None, reason="fixture")
    ledger.complete_incident(
        cpu_alert.alert_id,
        rca=rca,
        evidence_sha256="1" * 64,
        jira_issue_key="CORE-100",
        jira_issue_url="https://example.atlassian.net/browse/CORE-100",
        slack_delivered=True,
    )
    return ledger


def command_result(name: str, stdout: str = "active\n", return_code: int = 0) -> CommandEvidence:
    return CommandEvidence(
        name=name,
        argv=["/usr/bin/systemctl", "is-active", "demo.service"],
        started_at=datetime.now(UTC),
        duration_ms=1,
        return_code=return_code,
        stdout=stdout,
        stderr="",
        sha256="2" * 64,
    )


def test_dry_run_validates_policy_but_does_not_restart(
    tmp_path: Path, cpu_alert, empty_history, monkeypatch
) -> None:
    ledger = completed_ledger(tmp_path, cpu_alert, empty_history)
    observed_names: list[str] = []

    def fake_execute(spec, **kwargs):
        observed_names.append(spec.name)
        return command_result(spec.name)

    monkeypatch.setattr("opspilot_enterprise.remediation.execute_read_only", fake_execute)
    engine = RemediationEngine(
        ledger=ledger,
        mode="dry_run",
        approval_secret="approval-secret",  # noqa: S106 - non-production test value
        allowed_services=["demo.service"],
        auto_runbooks=[],
    )
    result = engine.execute(
        RemediationRequest(
            alert_id=cpu_alert.alert_id,
            runbook_id="restart.allowed_service",
            parameters={"service": "demo.service"},
            approved_by="alice@example.com",
            change_ticket="CHG-1001",
            approval_token="not-used-in-dry-run",  # noqa: S106 - test dry-run value
        )
    )
    assert result.status == "dry_run"
    assert observed_names == ["precheck_service_active"]


def test_non_allowlisted_service_is_denied(tmp_path: Path, cpu_alert, empty_history) -> None:
    ledger = completed_ledger(tmp_path, cpu_alert, empty_history)
    engine = RemediationEngine(
        ledger=ledger,
        mode="approval",
        approval_secret="approval-secret",  # noqa: S106 - non-production test value
        allowed_services=["safe.service"],
        auto_runbooks=[],
    )
    token = approval_token(
        "approval-secret",
        alert_id=cpu_alert.alert_id,
        runbook_id="restart.allowed_service",
        approved_by="alice@example.com",
        expires_at=2_000_000_000,
    )
    with pytest.raises(RemediationDenied, match="allowlist"):
        engine.execute(
            RemediationRequest(
                alert_id=cpu_alert.alert_id,
                runbook_id="restart.allowed_service",
                parameters={"service": "unsafe.service"},
                approved_by="alice@example.com",
                change_ticket="CHG-1002",
                approval_token=token,
            )
        )
