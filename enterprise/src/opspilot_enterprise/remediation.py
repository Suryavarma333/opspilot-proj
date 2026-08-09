"""Policy-gated remediation executor with fixed runbooks and no model-supplied commands."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from .ledger import IncidentLedger
from .models import (
    CommandEvidence,
    RemediationRequest,
    RemediationResult,
    RootCauseAnalysis,
    RootCauseClass,
)
from .security import verify_approval_token
from .telemetry import CommandSpec, execute_read_only


class RemediationDenied(RuntimeError):
    pass


class RemediationEngine:
    """Execute only compiled runbooks after independent policy validation.

    The current reference runbook is intentionally narrow: restart one explicitly
    allowlisted systemd service. Production deployments should run this class in a
    separate root-owned service behind a Unix socket, not in the web API process.
    """

    def __init__(
        self,
        *,
        ledger: IncidentLedger,
        mode: Literal["disabled", "dry_run", "approval", "auto"],
        approval_secret: str,
        allowed_services: list[str],
        auto_runbooks: list[str],
    ) -> None:
        self.ledger = ledger
        self.mode = mode
        self.approval_secret = approval_secret
        self.allowed_services = set(allowed_services)
        self.auto_runbooks = set(auto_runbooks)

    def execute(self, request: RemediationRequest) -> RemediationResult:
        started = datetime.now(UTC)
        incident = self.ledger.get_incident(request.alert_id)
        if not incident:
            raise RemediationDenied("unknown incident")
        if self.mode == "disabled":
            raise RemediationDenied("remediation is disabled")
        if incident.get("status") != "complete" or not incident.get("rca"):
            raise RemediationDenied("incident does not have a completed RCA")
        rca = RootCauseAnalysis.model_validate(incident["rca"])
        if rca.summary.classification == RootCauseClass.MANUALLY_INJECTED_LOAD:
            raise RemediationDenied(
                "service restart is not an appropriate automatic response to a load test"
            )
        if request.runbook_id != "restart.allowed_service":
            raise RemediationDenied("runbook is not registered")
        if rca.resolution.recommended_runbook_id not in {
            request.runbook_id,
            "investigate.resource_saturation",
        }:
            raise RemediationDenied("requested runbook is not consistent with the RCA")
        service = request.parameters.get("service", "")
        if service not in self.allowed_services:
            raise RemediationDenied("service is not in the remediation allowlist")

        if self.mode in {"approval", "auto"} and not verify_approval_token(
            request.approval_token,
            self.approval_secret,
            alert_id=request.alert_id,
            runbook_id=request.runbook_id,
            approved_by=request.approved_by,
        ):
            raise RemediationDenied("approval token is invalid or expired")
        if self.mode == "auto":
            if request.runbook_id not in self.auto_runbooks:
                raise RemediationDenied("runbook is not approved for automatic mode")
            if not rca.resolution.automation_eligible:
                raise RemediationDenied("RCA did not mark this runbook automation-eligible")
            if rca.summary.confidence != "high":
                raise RemediationDenied("automatic mode requires high-confidence RCA")

        if not self.ledger.begin_remediation(
            request.alert_id,
            request.runbook_id,
            request.change_ticket,
            request.approved_by,
            request.model_dump(mode="json", exclude={"approval_token"}),
        ):
            raise RemediationDenied("this remediation/change-ticket combination already ran")

        precheck = [
            execute_read_only(
                CommandSpec(
                    name="precheck_service_active",
                    argv=("systemctl", "is-active", service),
                    timeout_seconds=10,
                )
            )
        ]
        if self.mode == "dry_run":
            result = RemediationResult(
                alert_id=request.alert_id,
                runbook_id=request.runbook_id,
                status="dry_run",
                started_at=started,
                completed_at=datetime.now(UTC),
                precheck=precheck,
                message=(
                    f"Policy accepted restart of {service}; dry-run mode prevented state change."
                ),
            )
            self.ledger.finish_remediation(
                request.alert_id,
                request.runbook_id,
                request.change_ticket,
                result.status,
                result.model_dump(mode="json"),
            )
            return result

        if precheck[0].return_code != 0 or precheck[0].stdout.strip() != "active":
            result = self._finish_failure(
                request,
                started,
                precheck,
                [],
                [],
                "Precheck failed: service was not active; no restart was attempted.",
            )
            return result

        execution = [
            execute_read_only(
                CommandSpec(
                    name="execute_service_restart",
                    argv=("systemctl", "restart", service),
                    timeout_seconds=60,
                ),
                default_timeout=60,
            )
        ]
        postcheck = [
            execute_read_only(
                CommandSpec(
                    name="postcheck_service_active",
                    argv=("systemctl", "is-active", service),
                    timeout_seconds=15,
                )
            )
        ]
        succeeded = (
            execution[0].return_code == 0
            and postcheck[0].return_code == 0
            and postcheck[0].stdout.strip() == "active"
        )
        result = RemediationResult(
            alert_id=request.alert_id,
            runbook_id=request.runbook_id,
            status="succeeded" if succeeded else "failed",
            started_at=started,
            completed_at=datetime.now(UTC),
            precheck=precheck,
            execution=execution,
            postcheck=postcheck,
            rollback=[],
            message=(
                f"Restarted {service} and verified active state."
                if succeeded
                else (
                    f"Restart or postcheck failed for {service}; no generic rollback is safe. "
                    "Escalate using the service-specific recovery runbook."
                )
            ),
        )
        self.ledger.finish_remediation(
            request.alert_id,
            request.runbook_id,
            request.change_ticket,
            result.status,
            result.model_dump(mode="json"),
        )
        return result

    def _finish_failure(
        self,
        request: RemediationRequest,
        started: datetime,
        precheck: list[CommandEvidence],
        execution: list[CommandEvidence],
        postcheck: list[CommandEvidence],
        message: str,
    ) -> RemediationResult:
        result = RemediationResult(
            alert_id=request.alert_id,
            runbook_id=request.runbook_id,
            status="failed",
            started_at=started,
            completed_at=datetime.now(UTC),
            precheck=precheck,
            execution=execution,
            postcheck=postcheck,
            message=message,
        )
        self.ledger.finish_remediation(
            request.alert_id,
            request.runbook_id,
            request.change_ticket,
            result.status,
            result.model_dump(mode="json"),
        )
        return result
