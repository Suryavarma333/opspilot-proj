"""Strict contracts shared by collectors, adapters, the ledger, and the orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class AlertKind(StrEnum):
    SERVER_CPU = "server_cpu"
    SERVER_MEMORY = "server_memory"
    SERVER_DISK = "server_disk"
    SERVER_OOM = "server_oom"
    ROUTER_INTERFACE = "router_interface"


class AlertState(StrEnum):
    FIRING = "firing"
    RESOLVED = "resolved"


class IncidentStatus(StrEnum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"
    RESOLVED = "resolved"


class RootCauseClass(StrEnum):
    MANUALLY_INJECTED_LOAD = "manually_injected_load"
    ORGANIC_CAPACITY = "organic_capacity_exhaustion"
    APPLICATION_DEFECT = "application_defect"
    KERNEL_OR_HARDWARE = "kernel_or_hardware"
    NETWORK_LINK = "network_link_or_provider"
    CONFIGURATION = "configuration_or_change"
    DEPENDENCY = "dependency_failure"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class AlertEvent(StrictModel):
    """Normalized inbound alert. `resource` makes correlation deterministic."""

    schema_version: Literal["1.0"] = "1.0"
    alert_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    kind: AlertKind
    state: AlertState
    source: str = Field(min_length=1, max_length=80)
    node: str = Field(min_length=1, max_length=253)
    resource: str = Field(min_length=1, max_length=253)
    metric: str = Field(min_length=1, max_length=128)
    severity: Literal["SEV-1", "SEV-2", "SEV-3", "SEV-4"]
    observed_value: float | int | str
    threshold: float | int | str
    occurred_at: datetime = Field(default_factory=utc_now)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
        return value.astimezone(UTC)

    @field_validator("labels", "annotations")
    @classmethod
    def bound_maps(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 64:
            raise ValueError("at most 64 entries are accepted")
        return {str(k)[:128]: str(v)[:1024] for k, v in value.items()}

    @property
    def resource_key(self) -> str:
        return f"{self.kind.value}:{self.node}:{self.resource}:{self.metric}".lower()


class CommandEvidence(StrictModel):
    name: str
    argv: list[str]
    started_at: datetime
    duration_ms: int = Field(ge=0)
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProcessRecord(StrictModel):
    pid: int = Field(gt=0)
    ppid: int = Field(ge=0)
    uid: int = Field(ge=0)
    user: str
    state: str
    comm: str
    executable: str | None = None
    cwd: str | None = None
    command_line: str
    command_argv: list[str]
    cpu_percent: float = Field(ge=0)
    memory_percent: float = Field(ge=0)
    elapsed_seconds: int = Field(ge=0)
    cgroup: list[str] = Field(default_factory=list)
    parent_chain: list[int] = Field(default_factory=list)
    executable_deleted: bool = False


class SyntheticFinding(StrictModel):
    pid: int
    classification: Literal["confirmed", "suspected"]
    confidence: Literal["high", "medium", "low"]
    tool: str
    exact_command: str
    signature: str
    rationale: str
    parent_chain: list[int] = Field(default_factory=list)


class HostTelemetry(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    node: str
    collected_at: datetime = Field(default_factory=utc_now)
    collector_errors: list[str] = Field(default_factory=list)
    commands: dict[str, CommandEvidence] = Field(default_factory=dict)
    processes: list[ProcessRecord] = Field(default_factory=list)
    synthetic_findings: list[SyntheticFinding] = Field(default_factory=list)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class InterfaceCounters(StrictModel):
    rx_bytes: int = Field(default=0, ge=0)
    tx_bytes: int = Field(default=0, ge=0)
    rx_packets: int = Field(default=0, ge=0)
    tx_packets: int = Field(default=0, ge=0)
    rx_errors: int = Field(default=0, ge=0)
    tx_errors: int = Field(default=0, ge=0)
    rx_drops: int = Field(default=0, ge=0)
    tx_drops: int = Field(default=0, ge=0)


class NetworkInterface(StrictModel):
    device_id: str
    name: str
    description: str = ""
    admin_status: Literal["up", "down", "unknown"] = "unknown"
    oper_status: Literal["up", "down", "degraded", "unknown"] = "unknown"
    speed_bps: int | None = Field(default=None, ge=0)
    mtu: int | None = Field(default=None, ge=0)
    mac_address: str | None = None
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    counters: InterfaceCounters = Field(default_factory=InterfaceCounters)
    last_changed_at: datetime | None = None
    vendor_fields: dict[str, Any] = Field(default_factory=dict)


class NetworkSnapshot(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    device_id: str
    vendor: str
    collected_at: datetime = Field(default_factory=utc_now)
    interfaces: list[NetworkInterface]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    warnings: list[str] = Field(default_factory=list)


class FlapAssessment(StrictModel):
    resource_key: str
    window_days: int = Field(ge=1, le=30)
    firing_count: int = Field(ge=0)
    resolved_count: int = Field(ge=0)
    complete_cycles: int = Field(ge=0)
    state_changes: int = Field(ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_flapping: bool
    threshold_cycles: int = Field(ge=1)


class HistoricalEvent(StrictModel):
    alert_id: str
    kind: AlertKind
    state: AlertState
    resource_key: str
    occurred_at: datetime
    observed_value: float | int | str
    threshold: float | int | str
    severity: str
    root_cause_class: RootCauseClass | None = None
    evidence_sha256: str | None = None


class TemporalContext(StrictModel):
    node: str
    generated_at: datetime = Field(default_factory=utc_now)
    window_days: int = Field(ge=1, le=30)
    event_count: int = Field(ge=0)
    same_resource: FlapAssessment
    events: list[HistoricalEvent]
    recurring_classifications: dict[str, int] = Field(default_factory=dict)


class EvidenceItem(StrictModel):
    source: Literal["alert", "process", "kernel", "network", "history", "system"]
    fact: str = Field(min_length=1, max_length=800)
    locator: str = Field(min_length=1, max_length=300)
    supports: str = Field(min_length=1, max_length=500)


class SummarySection(StrictModel):
    headline: str = Field(min_length=1, max_length=240)
    impact: str = Field(min_length=1, max_length=800)
    root_cause: str = Field(min_length=1, max_length=1200)
    classification: RootCauseClass
    confidence: Literal["low", "medium", "high"]
    synthetic_load_detected: bool
    exact_injector_command: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def synthetic_command_consistency(self) -> SummarySection:
        if self.classification == RootCauseClass.MANUALLY_INJECTED_LOAD and (
            not self.synthetic_load_detected or not self.exact_injector_command
        ):
            raise ValueError("manual-load classification requires the detected exact command")
        return self


class HistorySection(StrictModel):
    finding: str = Field(min_length=1, max_length=1000)
    flapping: bool
    complete_cycles: int = Field(ge=0)
    window_days: int = Field(ge=1, le=30)
    prior_incident_count: int = Field(ge=0)


class ResolutionStep(StrictModel):
    order: int = Field(ge=1, le=10)
    action: str = Field(min_length=1, max_length=800)
    validation: str = Field(min_length=1, max_length=600)
    risk: Literal["low", "medium", "high"]
    requires_human_approval: bool = True


class ResolutionSection(StrictModel):
    immediate_containment: list[ResolutionStep] = Field(min_length=1, max_length=5)
    permanent_fix: list[ResolutionStep] = Field(min_length=1, max_length=5)
    recommended_runbook_id: str | None = Field(default=None, max_length=100)
    automation_eligible: bool
    rollback: str = Field(min_length=1, max_length=800)
    success_criteria: list[str] = Field(min_length=1, max_length=8)


class RootCauseAnalysis(StrictModel):
    """The required four-part RCA. Extra keys are rejected."""

    schema_version: Literal["opspilot.rca.v2"] = "opspilot.rca.v2"
    summary: SummarySection
    evidence: list[EvidenceItem] = Field(min_length=1, max_length=12)
    history: HistorySection
    resolution: ResolutionSection


class OrchestrationResult(StrictModel):
    alert_id: str
    status: IncidentStatus
    duplicate: bool = False
    evidence_sha256: str | None = None
    rca: RootCauseAnalysis | None = None
    jira_issue_key: str | None = None
    slack_delivered: bool = False
    errors: list[str] = Field(default_factory=list)


class RemediationRequest(StrictModel):
    alert_id: str
    runbook_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{2,99}$")
    parameters: dict[str, str] = Field(default_factory=dict)
    approved_by: str = Field(min_length=3, max_length=200)
    change_ticket: str = Field(min_length=3, max_length=80)
    approval_token: str = Field(min_length=16, max_length=512)


class RemediationResult(StrictModel):
    alert_id: str
    runbook_id: str
    status: Literal["denied", "dry_run", "succeeded", "failed", "rolled_back"]
    started_at: datetime
    completed_at: datetime
    precheck: list[CommandEvidence] = Field(default_factory=list)
    execution: list[CommandEvidence] = Field(default_factory=list)
    postcheck: list[CommandEvidence] = Field(default_factory=list)
    rollback: list[CommandEvidence] = Field(default_factory=list)
    message: str
