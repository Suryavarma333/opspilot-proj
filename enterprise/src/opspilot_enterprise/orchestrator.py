"""Central alert-to-evidence-to-RCA-to-Jira/Slack orchestration."""

from __future__ import annotations

import logging
import socket
from typing import Any

from .evidence import EvidenceStore
from .integrations import (
    IntegrationError,
    JiraClient,
    SlackWebhookClient,
    slack_webhook_payload,
)
from .ledger import IncidentLedger, LedgerError
from .llm import BharatRouterLLMClient, LlmResult, deterministic_fallback
from .models import (
    AlertEvent,
    AlertKind,
    AlertState,
    HostTelemetry,
    IncidentStatus,
    NetworkSnapshot,
    OrchestrationResult,
    RootCauseAnalysis,
)
from .network import RouterApiError, RouterTelemetryClient
from .prompt import PROMPT_VERSION, build_evidence_envelope, build_user_prompt
from .security import evidence_hash, redact_text
from .telemetry import ForensicTelemetryCollector

logger = logging.getLogger(__name__)


class OpsPilotOrchestrator:
    def __init__(
        self,
        *,
        ledger: IncidentLedger,
        evidence_store: EvidenceStore,
        telemetry: ForensicTelemetryCollector,
        llm: BharatRouterLLMClient | None,
        router: RouterTelemetryClient | None = None,
        jira: JiraClient | None = None,
        slack: SlackWebhookClient | None = None,
        history_window_days: int = 30,
        flapping_window_days: int = 7,
        flapping_cycle_threshold: int = 5,
        history_event_limit: int = 100,
    ) -> None:
        self.ledger = ledger
        self.evidence_store = evidence_store
        self.telemetry = telemetry
        self.llm = llm
        self.router = router
        self.jira = jira
        self.slack = slack
        self.history_window_days = history_window_days
        self.flapping_window_days = flapping_window_days
        self.flapping_cycle_threshold = flapping_cycle_threshold
        self.history_event_limit = history_event_limit

    def process(self, alert: AlertEvent) -> OrchestrationResult:
        existing = self.ledger.get_incident(alert.alert_id)
        if existing is None:
            self.ledger.register_alert(alert)
            existing = self.ledger.get_incident(alert.alert_id)
        if alert.state == AlertState.RESOLVED:
            return OrchestrationResult(
                alert_id=alert.alert_id,
                status=IncidentStatus.RESOLVED,
                duplicate=bool(existing),
                evidence_sha256=(existing or {}).get("evidence_sha256"),
                jira_issue_key=(existing or {}).get("jira_issue_key"),
                slack_delivered=bool((existing or {}).get("slack_delivered")),
            )

        claimed, row = self.ledger.claim_incident(alert.alert_id)
        if not claimed:
            if row is None:
                raise LedgerError(f"incident disappeared: {alert.alert_id}")
            parsed_rca = (
                RootCauseAnalysis.model_validate_json(row["rca_json"]) if row["rca_json"] else None
            )
            status = IncidentStatus(row["status"])
            return OrchestrationResult(
                alert_id=alert.alert_id,
                status=status,
                duplicate=True,
                evidence_sha256=row["evidence_sha256"],
                rca=parsed_rca,
                jira_issue_key=row["jira_issue_key"],
                slack_delivered=bool(row["slack_delivered"]),
                errors=[row["last_error"]] if row["last_error"] else [],
            )

        errors: list[str] = []
        try:
            host = self._collect_host(alert, errors)
            network = self._collect_network(alert, errors)
            history = self.ledger.temporal_context(
                alert,
                window_days=self.history_window_days,
                flapping_window_days=self.flapping_window_days,
                threshold_cycles=self.flapping_cycle_threshold,
                limit=self.history_event_limit,
            )
            envelope = build_evidence_envelope(alert, host=host, network=network, history=history)
            user_prompt, combined_sha = build_user_prompt(envelope)
            stored = self.evidence_store.write(alert.alert_id, envelope)
            if stored.sha256 != combined_sha:
                raise RuntimeError("evidence persistence hash mismatch")
            self.ledger.save_evidence(
                alert.alert_id,
                "forensic-envelope-v2",
                envelope,
                combined_sha,
                host.collected_at
                if host
                else (network.collected_at if network else alert.occurred_at),
            )

            llm_result = self._analyze(alert, history, host, user_prompt, combined_sha)
            self.ledger.record_llm_run(
                alert_id=alert.alert_id,
                provider=llm_result.provider,
                model=llm_result.model,
                route=llm_result.route,
                prompt_version=llm_result.prompt_version,
                prompt_sha256=llm_result.prompt_sha256,
                evidence_sha256=combined_sha,
                response_sha256=llm_result.response_sha256,
                latency_ms=llm_result.latency_ms,
                status="fallback" if llm_result.fallback_used else "succeeded",
                error=llm_result.error,
            )
            if llm_result.error:
                errors.append(f"llm_fallback:{llm_result.error}")

            jira_key, jira_url = self._deliver_jira(alert, llm_result, combined_sha, errors)
            slack_delivered = self._deliver_slack(
                alert, llm_result.rca, combined_sha, jira_key, jira_url, errors
            )
            self.ledger.complete_incident(
                alert.alert_id,
                rca=llm_result.rca,
                evidence_sha256=combined_sha,
                jira_issue_key=jira_key,
                jira_issue_url=jira_url,
                slack_delivered=slack_delivered,
                errors=errors,
            )
            return OrchestrationResult(
                alert_id=alert.alert_id,
                status=IncidentStatus.COMPLETE,
                evidence_sha256=combined_sha,
                rca=llm_result.rca,
                jira_issue_key=jira_key,
                slack_delivered=slack_delivered,
                errors=errors,
            )
        except Exception as error:
            safe_error, _ = redact_text(f"{type(error).__name__}: {error}", max_chars=4000)
            self.ledger.fail_incident(alert.alert_id, safe_error)
            logger.exception(
                "incident orchestration failed",
                extra={"context": {"alert_id": alert.alert_id, "error": safe_error}},
            )
            raise

    def _collect_host(self, alert: AlertEvent, errors: list[str]) -> HostTelemetry | None:
        if alert.kind == AlertKind.ROUTER_INTERFACE:
            return None
        local_names = {socket.gethostname(), socket.getfqdn(), "localhost", "127.0.0.1"}
        if alert.node not in local_names:
            errors.append(
                "host_telemetry_not_collected: alert node is not this collector; deploy the "
                "node agent or submit a signed evidence bundle"
            )
            return None
        return self.telemetry.collect(since_minutes=10)

    def _collect_network(self, alert: AlertEvent, errors: list[str]) -> NetworkSnapshot | None:
        if alert.kind != AlertKind.ROUTER_INTERFACE:
            return None
        if not self.router:
            errors.append("router_telemetry_not_collected: no hardware router adapter configured")
            return None
        try:
            snapshot = self.router.fetch_interfaces(alert.node)
        except RouterApiError as error:
            errors.append(f"router_telemetry_failed:{error}")
            return None
        if not any(interface.name == alert.resource for interface in snapshot.interfaces):
            errors.append(f"router_interface_missing:{alert.resource}")
        return snapshot

    def _analyze(
        self,
        alert: AlertEvent,
        history: Any,
        host: HostTelemetry | None,
        user_prompt: str,
        combined_sha: str,
    ) -> LlmResult:
        prompt_sha = evidence_hash(
            {"system_prompt_version": PROMPT_VERSION, "user_prompt": user_prompt}
        )
        if self.llm:
            return self.llm.analyze(
                alert=alert,
                history=history,
                host=host,
                user_prompt=user_prompt,
                prompt_sha256=prompt_sha,
            )
        fallback = deterministic_fallback(
            alert, history, host, reason="BharatRouter LLM client is not configured"
        )
        return LlmResult(
            rca=fallback,
            provider="disabled",
            model="none",
            route=None,
            prompt_version=PROMPT_VERSION,
            prompt_sha256=prompt_sha,
            response_sha256=evidence_hash(fallback.model_dump(mode="json")),
            latency_ms=0,
            fallback_used=True,
            error="provider_not_configured",
        )

    def _deliver_jira(
        self,
        alert: AlertEvent,
        llm_result: LlmResult,
        combined_sha: str,
        errors: list[str],
    ) -> tuple[str | None, str | None]:
        if not self.jira:
            errors.append("jira_not_configured")
            return None, None
        if not self.ledger.reserve_delivery(alert.alert_id, "jira", "rca"):
            incident = self.ledger.get_incident(alert.alert_id) or {}
            return incident.get("jira_issue_key"), incident.get("jira_issue_url")
        try:
            outcome = self.jira.create_or_find(
                alert,
                llm_result.rca,
                evidence_sha256=combined_sha,
                prompt_version=llm_result.prompt_version,
                model=llm_result.model,
            )
            self.ledger.finish_delivery(
                alert.alert_id,
                "jira",
                "rca",
                state="sent",
                external_id=outcome.external_id,
                response_sha256=outcome.response_sha256,
            )
            return outcome.external_id, outcome.external_url
        except IntegrationError as error:
            state = "unknown" if error.outcome_unknown else "failed"
            self.ledger.finish_delivery(
                alert.alert_id, "jira", "rca", state=state, error=str(error)
            )
            errors.append(f"jira_{state}:{error}")
            return None, None

    def _deliver_slack(
        self,
        alert: AlertEvent,
        rca: RootCauseAnalysis,
        combined_sha: str,
        jira_key: str | None,
        jira_url: str | None,
        errors: list[str],
    ) -> bool:
        if not self.slack:
            errors.append("slack_not_configured")
            return False
        if not self.ledger.reserve_delivery(alert.alert_id, "slack", "rca"):
            incident = self.ledger.get_incident(alert.alert_id) or {}
            return bool(incident.get("slack_delivered"))
        payload = slack_webhook_payload(
            alert,
            rca,
            evidence_sha256=combined_sha,
            jira_key=jira_key,
            jira_url=jira_url,
        )
        try:
            outcome = self.slack.post(payload)
            self.ledger.finish_delivery(
                alert.alert_id,
                "slack",
                "rca",
                state="sent",
                response_sha256=outcome.response_sha256,
            )
            return True
        except IntegrationError as error:
            state = "unknown" if error.outcome_unknown else "failed"
            self.ledger.finish_delivery(
                alert.alert_id, "slack", "rca", state=state, error=str(error)
            )
            errors.append(f"slack_{state}:{error}")
            return False
