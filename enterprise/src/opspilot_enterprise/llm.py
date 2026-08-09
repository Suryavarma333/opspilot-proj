"""BharatRouter LLM client, strict RCA parsing, and deterministic fallback."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import SecretStr, ValidationError

from .models import (
    AlertEvent,
    EvidenceItem,
    HistorySection,
    HostTelemetry,
    ResolutionSection,
    ResolutionStep,
    RootCauseAnalysis,
    RootCauseClass,
    SummarySection,
    TemporalContext,
)
from .prompt import MASTER_SYSTEM_PROMPT, PROMPT_VERSION, rca_json_schema
from .security import evidence_hash, redact_text


class LlmError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


@dataclass(frozen=True)
class LlmResult:
    rca: RootCauseAnalysis
    provider: str
    model: str
    route: str | None
    prompt_version: str
    prompt_sha256: str
    response_sha256: str
    latency_ms: int
    fallback_used: bool
    error: str | None = None


def _content_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return ""


def _parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            raise LlmError("model response did not contain a JSON object") from None
        try:
            value = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError as error:
            raise LlmError("model response contained invalid JSON") from error
    if not isinstance(value, dict):
        raise LlmError("model response JSON must be an object")
    return value


def deterministic_fallback(
    alert: AlertEvent,
    history: TemporalContext,
    host: HostTelemetry | None,
    *,
    reason: str,
) -> RootCauseAnalysis:
    finding = host.synthetic_findings[0] if host and host.synthetic_findings else None
    if finding and finding.confidence == "high":
        classification = RootCauseClass.MANUALLY_INJECTED_LOAD
        confidence: Literal["low", "medium", "high"] = "high"
        root_cause = (
            f"A deterministic {finding.tool} signature is present in PID {finding.pid}; "
            "its exact process arguments show an intentionally generated workload."
        )
        headline = "The alert coincides with a confirmed manually injected load."
        exact_command = finding.exact_command
        synthetic = True
        locator = f"host.synthetic_findings[pid={finding.pid}]"
        fact = f"Detected {finding.tool}: {finding.exact_command[:500]}"
        runbook = "inspect.synthetic_load"
    else:
        classification = RootCauseClass.INSUFFICIENT_EVIDENCE
        confidence = "low"
        root_cause = (
            "The alert threshold is established, but the available deterministic evidence does "
            f"not prove a single cause; AI analysis was unavailable ({reason[:300]})."
        )
        headline = f"{alert.kind.value} alert requires engineer validation."
        exact_command = None
        synthetic = False
        locator = "alert"
        fact = (
            f"{alert.metric} observed={alert.observed_value} threshold={alert.threshold} "
            f"state={alert.state.value}"
        )
        runbook = (
            "investigate.interface_flap"
            if alert.kind.value == "router_interface"
            else "investigate.resource_saturation"
        )

    return RootCauseAnalysis(
        summary=SummarySection(
            headline=headline,
            impact=(
                f"{alert.node}/{alert.resource} reported {alert.metric}={alert.observed_value} "
                f"against threshold {alert.threshold}."
            ),
            root_cause=root_cause,
            classification=classification,
            confidence=confidence,
            synthetic_load_detected=synthetic,
            exact_injector_command=exact_command,
        ),
        evidence=[
            EvidenceItem(
                source="process" if finding else "alert",
                fact=fact,
                locator=locator,
                supports="the deterministic fallback classification",
            )
        ],
        history=HistorySection(
            finding=(
                f"The ledger contains {history.event_count} transitions in {history.window_days} "
                f"days; this resource has {history.same_resource.complete_cycles} complete cycles."
            ),
            flapping=history.same_resource.is_flapping,
            complete_cycles=history.same_resource.complete_cycles,
            window_days=history.same_resource.window_days,
            prior_incident_count=max(0, history.event_count - 1),
        ),
        resolution=ResolutionSection(
            immediate_containment=[
                ResolutionStep(
                    order=1,
                    action=(
                        "Confirm the workload owner and stop the controlled test through the "
                        "approved test procedure"
                        if finding
                        else (
                            "Validate the alert against the frozen read-only telemetry and the "
                            "approved runbook"
                        )
                    ),
                    validation=(
                        f"Confirm {alert.metric} returns below {alert.threshold} without new impact"
                    ),
                    risk="low",
                    requires_human_approval=True,
                )
            ],
            permanent_fix=[
                ResolutionStep(
                    order=1,
                    action=(
                        "Tag planned load tests and suppress only their approved alert window"
                        if finding
                        else (
                            "Collect the missing causal telemetry and update the "
                            "resource-specific runbook"
                        )
                    ),
                    validation="Review one controlled recurrence and confirm evidence quality",
                    risk="low",
                    requires_human_approval=True,
                )
            ],
            recommended_runbook_id=runbook,
            automation_eligible=False,
            rollback=(
                "No automated state change was made; revert any human change through its "
                "approved change record."
            ),
            success_criteria=[
                "The monitored metric is stable below threshold",
                "No new firing transition appears during the validation interval",
            ],
        ),
    )


def enforce_deterministic_findings(
    rca: RootCauseAnalysis, host: HostTelemetry | None
) -> RootCauseAnalysis:
    findings = host.synthetic_findings if host else []
    decisive = next((item for item in findings if item.confidence == "high"), None)
    if decisive:
        summary = rca.summary.model_copy(
            update={
                "classification": RootCauseClass.MANUALLY_INJECTED_LOAD,
                "confidence": "high",
                "synthetic_load_detected": True,
                "exact_injector_command": decisive.exact_command,
                "root_cause": (
                    f"A deterministic {decisive.tool} signature was captured in PID "
                    f"{decisive.pid}: {decisive.rationale}. " + rca.summary.root_cause
                )[:1200],
            }
        )
        evidence = list(rca.evidence)
        if not any(
            item.locator == f"host.synthetic_findings[pid={decisive.pid}]" for item in evidence
        ):
            evidence.insert(
                0,
                EvidenceItem(
                    source="process",
                    fact=f"{decisive.tool} exact command: {decisive.exact_command[:500]}",
                    locator=f"host.synthetic_findings[pid={decisive.pid}]",
                    supports="manual injected load classification",
                ),
            )
        return rca.model_copy(update={"summary": summary, "evidence": evidence[:12]})
    if rca.summary.classification == RootCauseClass.MANUALLY_INJECTED_LOAD:
        summary = rca.summary.model_copy(
            update={
                "classification": RootCauseClass.INSUFFICIENT_EVIDENCE,
                "confidence": "low",
                "synthetic_load_detected": False,
                "exact_injector_command": None,
                "root_cause": (
                    "The model proposed manual load, but the deterministic process classifier "
                    "found no qualifying command signature; manual injection is therefore unproven."
                ),
            }
        )
        return rca.model_copy(update={"summary": summary})
    return rca


class BharatRouterLLMClient:
    """OpenAI-wire-format chat-completions client for BharatRouter."""

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model: str,
        base_url: str = "https://api.bharatrouter.com/v1",
        optimize: str = "uptime",
        data_policy: str | None = "india_only",
        timeout_seconds: float = 90,
        max_output_tokens: int = 2800,
        response_format: Literal["json_schema", "json_object", "none"] = "json_schema",
        max_attempts: int = 3,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.optimize = optimize
        self.data_policy = data_policy
        self.timeout_seconds = timeout_seconds
        self.max_output_tokens = max_output_tokens
        self.response_format = response_format
        self.max_attempts = max_attempts
        self.transport = transport

    def analyze(
        self,
        *,
        alert: AlertEvent,
        history: TemporalContext,
        host: HostTelemetry | None,
        user_prompt: str,
        prompt_sha256: str,
    ) -> LlmResult:
        started = time.monotonic()
        headers = {
            "Authorization": f"Bearer {self.api_key.get_secret_value()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": MASTER_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": self.max_output_tokens,
            "stream": False,
            "optimize": self.optimize,
        }
        if self.data_policy:
            payload["data_policy"] = self.data_policy
        if self.response_format == "json_schema":
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "opspilot_root_cause_analysis",
                    "strict": True,
                    "schema": rca_json_schema(),
                },
            }
        elif self.response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}

        try:
            try:
                content, route = self._post(payload, headers)
            except LlmError as strict_error:
                if self.response_format != "json_schema" or strict_error.status_code != 400:
                    raise
                compatible_payload = dict(payload)
                compatible_payload["response_format"] = {"type": "json_object"}
                content, route = self._post(compatible_payload, headers)
            parsed = _parse_json_object(content)
            rca = enforce_deterministic_findings(RootCauseAnalysis.model_validate(parsed), host)
            response_sha = evidence_hash(rca.model_dump(mode="json"))
            return LlmResult(
                rca=rca,
                provider="bharatrouter",
                model=self.model,
                route=route,
                prompt_version=PROMPT_VERSION,
                prompt_sha256=prompt_sha256,
                response_sha256=response_sha,
                latency_ms=int((time.monotonic() - started) * 1000),
                fallback_used=False,
            )
        except (LlmError, ValidationError, httpx.HTTPError) as error:
            safe_error, _ = redact_text(f"{type(error).__name__}: {error}", max_chars=1000)
            fallback = deterministic_fallback(alert, history, host, reason=safe_error)
            return LlmResult(
                rca=fallback,
                provider="bharatrouter",
                model=self.model,
                route=None,
                prompt_version=PROMPT_VERSION,
                prompt_sha256=prompt_sha256,
                response_sha256=evidence_hash(fallback.model_dump(mode="json")),
                latency_ms=int((time.monotonic() - started) * 1000),
                fallback_used=True,
                error=safe_error,
            )

    def _post(self, payload: dict[str, Any], headers: dict[str, str]) -> tuple[str, str | None]:
        last_error: Exception | None = None
        with httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            for attempt in range(1, self.max_attempts + 1):
                try:
                    response = client.post(
                        f"{self.base_url}/chat/completions", headers=headers, json=payload
                    )
                except (httpx.TimeoutException, httpx.NetworkError) as error:
                    last_error = LlmError(
                        f"BharatRouter transport failure: {type(error).__name__}", retryable=True
                    )
                    if attempt == self.max_attempts:
                        raise last_error from error
                    time.sleep(min(8, (2 ** (attempt - 1)) + secrets.randbelow(1000) / 1000))
                    continue
                if response.status_code == 200:
                    try:
                        body = response.json()
                        message = body["choices"][0]["message"]
                    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as error:
                        raise LlmError(
                            "BharatRouter returned an invalid completion envelope"
                        ) from error
                    content = _content_text(message)
                    if not content:
                        refusal = message.get("refusal") if isinstance(message, dict) else None
                        raise LlmError(
                            f"BharatRouter returned no RCA content; refusal={bool(refusal)}"
                        )
                    return content, response.headers.get("x-br-provider")

                retryable = response.status_code in {408, 425, 429, 500, 502, 503, 504}
                try:
                    body = response.json()
                    detail = body.get("error", {}).get("code") or body.get("error", {}).get(
                        "message"
                    )
                except (json.JSONDecodeError, AttributeError):
                    detail = response.text
                safe_detail, _ = redact_text(str(detail), max_chars=500)
                last_error = LlmError(
                    f"BharatRouter HTTP {response.status_code}: {safe_detail}",
                    retryable=retryable,
                    status_code=response.status_code,
                )
                if not retryable or attempt == self.max_attempts:
                    raise last_error
                retry_after = response.headers.get("retry-after")
                try:
                    delay = min(30, max(0, float(retry_after))) if retry_after else None
                except ValueError:
                    delay = None
                time.sleep(
                    delay
                    if delay is not None
                    else min(8, (2 ** (attempt - 1)) + secrets.randbelow(1000) / 1000)
                )
        raise LlmError(f"BharatRouter request failed: {last_error}")
