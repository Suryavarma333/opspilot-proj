"""Dependency construction from validated Settings."""

from __future__ import annotations

from .config import Settings
from .evidence import EvidenceStore
from .integrations import JiraClient, SlackWebhookClient
from .ledger import IncidentLedger
from .llm import BharatRouterLLMClient
from .network import HardwareFlapDetector, RouterTelemetryClient
from .orchestrator import OpsPilotOrchestrator
from .remediation import RemediationEngine
from .telemetry import ForensicTelemetryCollector


def build_ledger(settings: Settings) -> IncidentLedger:
    ledger = IncidentLedger(settings.state_db)
    ledger.initialize()
    return ledger


def build_router(settings: Settings) -> RouterTelemetryClient | None:
    if not settings.router_base_url or not settings.router_api_key:
        return None
    return RouterTelemetryClient(
        base_url=settings.router_base_url,
        api_key=settings.router_api_key,
        auth_header=settings.router_auth_header,
        interfaces_path=settings.router_interfaces_path,
        timeout_seconds=settings.router_timeout_seconds,
    )


def build_orchestrator(
    settings: Settings, ledger: IncidentLedger | None = None
) -> OpsPilotOrchestrator:
    ledger = ledger or build_ledger(settings)
    llm = (
        BharatRouterLLMClient(
            api_key=settings.bharatrouter_api_key,
            model=settings.llm_model,
            base_url=settings.bharatrouter_base_url,
            optimize=settings.llm_optimize,
            data_policy=settings.llm_data_policy,
            timeout_seconds=settings.llm_timeout_seconds,
            max_output_tokens=settings.llm_max_output_tokens,
            response_format=settings.llm_response_format,
        )
        if settings.bharatrouter_api_key
        else None
    )
    jira = None
    if settings.jira_base_url and settings.jira_project_key:
        jira = JiraClient(
            base_url=settings.jira_base_url,
            project_key=settings.jira_project_key,
            issue_type=settings.jira_issue_type,
            user_email=settings.jira_user_email,
            api_token=settings.jira_api_token,
            bearer_token=settings.jira_bearer_token,
        )
    slack = SlackWebhookClient(settings.slack_webhook_url) if settings.slack_webhook_url else None
    return OpsPilotOrchestrator(
        ledger=ledger,
        evidence_store=EvidenceStore(settings.evidence_dir),
        telemetry=ForensicTelemetryCollector(
            command_timeout_seconds=settings.telemetry_command_timeout_seconds,
            total_budget_seconds=settings.telemetry_total_budget_seconds,
            max_command_bytes=settings.telemetry_max_command_bytes,
            max_processes=settings.telemetry_max_processes,
            cpu_sample_seconds=settings.telemetry_cpu_sample_seconds,
        ),
        llm=llm,
        router=build_router(settings),
        jira=jira,
        slack=slack,
        history_window_days=settings.history_window_days,
        flapping_window_days=settings.flapping_window_days,
        flapping_cycle_threshold=settings.flapping_cycle_threshold,
        history_event_limit=settings.history_event_limit,
    )


def build_remediation(settings: Settings, ledger: IncidentLedger) -> RemediationEngine:
    return RemediationEngine(
        ledger=ledger,
        mode=settings.remediation_mode,
        approval_secret=settings.approval_hmac_secret.get_secret_value(),
        allowed_services=settings.remediation_allowed_services,
        auto_runbooks=settings.remediation_auto_runbooks,
    )


def build_flap_detector(settings: Settings, ledger: IncidentLedger) -> HardwareFlapDetector:
    return HardwareFlapDetector(
        ledger,
        window_days=settings.flapping_window_days,
        cycle_threshold=settings.flapping_cycle_threshold,
    )
