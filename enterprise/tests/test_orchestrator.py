from __future__ import annotations

import socket
from pathlib import Path

from opspilot_enterprise.evidence import EvidenceStore
from opspilot_enterprise.ledger import IncidentLedger
from opspilot_enterprise.models import HostTelemetry, SyntheticFinding
from opspilot_enterprise.orchestrator import OpsPilotOrchestrator


class SyntheticCollector:
    def collect(self, *, since_minutes: int = 10) -> HostTelemetry:
        return HostTelemetry(
            node=socket.gethostname(),
            evidence_sha256="e" * 64,
            synthetic_findings=[
                SyntheticFinding(
                    pid=9001,
                    classification="confirmed",
                    confidence="high",
                    tool="stress-ng",
                    exact_command="/usr/bin/stress-ng --cpu 8 --timeout 60",
                    signature="known-tool:stress-ng",
                    rationale="stress-ng is an explicit workload generator",
                    parent_chain=[8000, 1],
                )
            ],
        )


def test_orchestrator_completes_with_deterministic_manual_load(tmp_path: Path, cpu_alert) -> None:
    local_alert = cpu_alert.model_copy(update={"node": socket.gethostname()})
    ledger = IncidentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_alert(local_alert)
    orchestrator = OpsPilotOrchestrator(
        ledger=ledger,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
        telemetry=SyntheticCollector(),  # type: ignore[arg-type]
        llm=None,
        jira=None,
        slack=None,
    )
    result = orchestrator.process(local_alert)
    assert result.status == "complete"
    assert result.rca is not None
    assert result.rca.summary.classification == "manually_injected_load"
    assert result.rca.summary.exact_injector_command == ("/usr/bin/stress-ng --cpu 8 --timeout 60")
    assert result.evidence_sha256
    assert list((tmp_path / "evidence").rglob("*.json.gz"))

    duplicate = orchestrator.process(local_alert)
    assert duplicate.duplicate
    assert duplicate.rca == result.rca
