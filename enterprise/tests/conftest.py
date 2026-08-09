from __future__ import annotations

from datetime import UTC, datetime

import pytest

from opspilot_enterprise.models import (
    AlertEvent,
    AlertKind,
    AlertState,
    FlapAssessment,
    TemporalContext,
)


@pytest.fixture
def cpu_alert() -> AlertEvent:
    return AlertEvent(
        alert_id="cpu-test-node-0001",
        kind=AlertKind.SERVER_CPU,
        state=AlertState.FIRING,
        source="pytest",
        node="test-node",
        resource="host",
        metric="cpu.utilization.percent",
        severity="SEV-1",
        observed_value=99.2,
        threshold=90,
        occurred_at=datetime(2026, 8, 5, 5, 0, tzinfo=UTC),
    )


@pytest.fixture
def empty_history(cpu_alert: AlertEvent) -> TemporalContext:
    return TemporalContext(
        node=cpu_alert.node,
        window_days=30,
        event_count=1,
        same_resource=FlapAssessment(
            resource_key=cpu_alert.resource_key,
            window_days=7,
            firing_count=1,
            resolved_count=0,
            complete_cycles=0,
            state_changes=0,
            is_flapping=False,
            threshold_cycles=5,
        ),
        events=[],
    )
