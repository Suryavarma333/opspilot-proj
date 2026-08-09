from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from opspilot_enterprise.ledger import IncidentLedger
from opspilot_enterprise.models import AlertEvent, AlertKind, AlertState


def transition(
    index: int,
    state: AlertState,
    occurred_at: datetime,
    *,
    alert_id: str | None = None,
) -> AlertEvent:
    return AlertEvent(
        alert_id=alert_id or f"router-cycle-{index:04d}",
        kind=AlertKind.ROUTER_INTERFACE,
        state=state,
        source="test-router",
        node="edge-router-01",
        resource="GigabitEthernet0/1",
        metric="oper_status",
        severity="SEV-2" if state == AlertState.FIRING else "SEV-4",
        observed_value="down" if state == AlertState.FIRING else "up",
        threshold="up",
        occurred_at=occurred_at,
    )


def test_register_alert_and_job_are_occurrence_idempotent(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path / "state.sqlite3")
    alert = transition(1, AlertState.FIRING, datetime(2026, 8, 1, tzinfo=UTC))
    first = ledger.register_alert(alert)
    second = ledger.register_alert(alert)
    assert first[0] is True and first[1] is not None
    assert second == (False, None)
    job = ledger.claim_job("worker-1", 60)
    assert job and job["alert_id"] == alert.alert_id
    assert ledger.claim_job("worker-2", 60) is None
    ledger.finish_job(job["id"], "worker-1", success=True)


def test_five_complete_cycles_in_week_are_flapping(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path / "state.sqlite3")
    start = datetime(2026, 8, 1, tzinfo=UTC)
    sample = transition(0, AlertState.FIRING, start)
    for index in range(5):
        alert_id = f"router-cycle-{index:04d}"
        ledger.register_alert(
            transition(
                index, AlertState.FIRING, start + timedelta(hours=index * 4), alert_id=alert_id
            )
        )
        ledger.register_alert(
            transition(
                index,
                AlertState.RESOLVED,
                start + timedelta(hours=index * 4 + 1),
                alert_id=alert_id,
            )
        )
    assessment = ledger.flap_assessment(
        sample.resource_key,
        window_days=7,
        threshold_cycles=5,
        now=start + timedelta(days=6),
    )
    assert assessment.firing_count == 5
    assert assessment.resolved_count == 5
    assert assessment.complete_cycles == 5
    assert assessment.state_changes == 9
    assert assessment.is_flapping


def test_temporal_context_is_bounded_to_node_and_window(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path / "state.sqlite3")
    now = datetime(2026, 8, 5, tzinfo=UTC)
    current = transition(1, AlertState.FIRING, now)
    ledger.register_alert(current)
    old = transition(2, AlertState.FIRING, now - timedelta(days=31))
    ledger.register_alert(old)
    context = ledger.temporal_context(current, window_days=30, now=now)
    assert context.event_count == 1
    assert context.events[0].alert_id == current.alert_id
    assert "same_resource" in ledger.history_for_llm(context)


def test_delivery_reservation_blocks_duplicate_and_unknown_retry(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path / "state.sqlite3")
    alert = transition(1, AlertState.FIRING, datetime(2026, 8, 5, tzinfo=UTC))
    ledger.register_alert(alert)
    assert ledger.reserve_delivery(alert.alert_id, "slack", "rca")
    assert not ledger.reserve_delivery(alert.alert_id, "slack", "rca")
    ledger.finish_delivery(alert.alert_id, "slack", "rca", state="unknown")
    assert not ledger.reserve_delivery(alert.alert_id, "slack", "rca")
