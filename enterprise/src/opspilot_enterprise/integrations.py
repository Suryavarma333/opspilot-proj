"""Jira and Slack delivery adapters with explicit duplicate/unknown handling."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from .models import AlertEvent, RootCauseAnalysis
from .security import evidence_hash, redact_text


@dataclass(frozen=True)
class DeliveryOutcome:
    state: str
    external_id: str | None
    external_url: str | None
    response_sha256: str | None
    error: str | None = None


class IntegrationError(RuntimeError):
    def __init__(self, message: str, *, outcome_unknown: bool = False):
        super().__init__(message)
        self.outcome_unknown = outcome_unknown


def _text(value: str) -> dict[str, Any]:
    return {"type": "text", "text": value}


def _paragraph(value: str) -> dict[str, Any]:
    return {"type": "paragraph", "content": [_text(value)]}


def _heading(value: str, level: int = 2) -> dict[str, Any]:
    return {"type": "heading", "attrs": {"level": level}, "content": [_text(value)]}


def _bullet_list(values: list[str], *, ordered: bool = False) -> dict[str, Any]:
    return {
        "type": "orderedList" if ordered else "bulletList",
        **({"attrs": {"order": 1}} if ordered else {}),
        "content": [{"type": "listItem", "content": [_paragraph(value)]} for value in values],
    }


def rca_adf_document(
    alert: AlertEvent,
    rca: RootCauseAnalysis,
    *,
    evidence_sha256: str,
    prompt_version: str,
    model: str,
) -> dict[str, Any]:
    summary = rca.summary
    history = rca.history
    content: list[dict[str, Any]] = [
        _heading("OpsPilot Incident", 1),
        _paragraph(
            f"{alert.severity} {alert.kind.value} on {alert.node}/{alert.resource}; "
            f"{alert.metric}={alert.observed_value}, threshold={alert.threshold}, "
            f"state={alert.state.value}, observed at {alert.occurred_at.isoformat()}."
        ),
        _heading("1. Summary"),
        _paragraph(summary.headline),
        _paragraph(f"Impact: {summary.impact}"),
        _paragraph(f"Root cause: {summary.root_cause}"),
        _paragraph(
            f"Classification: {summary.classification.value}; confidence: {summary.confidence}; "
            f"synthetic load: {'yes' if summary.synthetic_load_detected else 'no'}."
        ),
    ]
    if summary.exact_injector_command:
        content.append(_paragraph(f"Exact injector command: {summary.exact_injector_command}"))
    content.extend(
        [
            _heading("2. Evidence"),
            _bullet_list(
                [
                    f"[{item.source}] {item.fact} (locator: {item.locator}; "
                    f"supports: {item.supports})"
                    for item in rca.evidence
                ]
            ),
            _heading("3. History"),
            _paragraph(history.finding),
            _paragraph(
                f"Flapping: {'yes' if history.flapping else 'no'}; complete cycles: "
                f"{history.complete_cycles}; window: {history.window_days} days; supplied prior "
                f"incidents/transitions: {history.prior_incident_count}."
            ),
            _heading("4. Resolution"),
            _heading("Immediate containment", 3),
            _bullet_list(
                [
                    f"{step.action} Validation: {step.validation} Risk: {step.risk}. "
                    "Human approval: "
                    f"{'required' if step.requires_human_approval else 'not required'}."
                    for step in rca.resolution.immediate_containment
                ],
                ordered=True,
            ),
            _heading("Permanent fix", 3),
            _bullet_list(
                [
                    f"{step.action} Validation: {step.validation} Risk: {step.risk}. "
                    "Human approval: "
                    f"{'required' if step.requires_human_approval else 'not required'}."
                    for step in rca.resolution.permanent_fix
                ],
                ordered=True,
            ),
            _paragraph(f"Rollback: {rca.resolution.rollback}"),
            _paragraph("Success criteria: " + "; ".join(rca.resolution.success_criteria)),
            _paragraph(
                "Advisory only. No remediation was executed by the AI. "
                f"Evidence SHA-256: {evidence_sha256}. Prompt: {prompt_version}. Model: {model}."
            ),
        ]
    )
    return {"version": 1, "type": "doc", "content": content}


def slack_webhook_payload(
    alert: AlertEvent,
    rca: RootCauseAnalysis,
    *,
    evidence_sha256: str,
    jira_key: str | None,
    jira_url: str | None,
) -> dict[str, Any]:
    summary = rca.summary
    evidence_lines = "\n".join(f"• *{item.source}:* {item.fact[:450]}" for item in rca.evidence[:6])
    containment = "\n".join(
        f"{index}. {step.action[:450]}"
        for index, step in enumerate(rca.resolution.immediate_containment, 1)
    )
    jira = f"<{jira_url}|{jira_key}>" if jira_key and jira_url else "not configured"
    fallback = (f"OpsPilot {alert.severity}: {summary.headline} on {alert.node}/{alert.resource}")[
        :3000
    ]
    return {
        "text": fallback,
        "unfurl_links": False,
        "unfurl_media": False,
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": (
                        f"OpsPilot {alert.severity} · {alert.kind.value.replace('_', ' ').title()}"
                    ),
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Node*\n`{alert.node[:200]}`"},
                    {"type": "mrkdwn", "text": f"*Resource*\n`{alert.resource[:200]}`"},
                    {"type": "mrkdwn", "text": f"*Observed*\n{str(alert.observed_value)[:200]}"},
                    {"type": "mrkdwn", "text": f"*Threshold*\n{str(alert.threshold)[:200]}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*1. Summary*\n{summary.headline[:600]}\n"
                        f"*Classification:* `{summary.classification.value}` · "
                        f"*Confidence:* `{summary.confidence}`\n{summary.root_cause[:1200]}"
                    ),
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*2. Evidence*\n{evidence_lines}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*3. History*\n{rca.history.finding[:1000]}\n"
                        f"Flapping: *{'yes' if rca.history.flapping else 'no'}* · "
                        f"cycles: `{rca.history.complete_cycles}`/{rca.history.window_days}d"
                    ),
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*4. Resolution (advisory)*\n{containment}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Jira: {jira} · Evidence `{evidence_sha256[:16]}…` · "
                            "AI cannot execute remediation"
                        ),
                    }
                ],
            },
        ],
    }


class JiraClient:
    def __init__(
        self,
        *,
        base_url: str,
        project_key: str,
        issue_type: str = "Incident",
        user_email: str | None = None,
        api_token: SecretStr | None = None,
        bearer_token: SecretStr | None = None,
        timeout_seconds: float = 20,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if bool(user_email and api_token) == bool(bearer_token):
            raise ValueError("configure exactly one Jira authentication method")
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.issue_type = issue_type
        self.timeout_seconds = timeout_seconds
        self.transport = transport
        self.auth = (
            httpx.BasicAuth(user_email, api_token.get_secret_value())
            if user_email and api_token
            else None
        )
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token.get_secret_value()}"

    @staticmethod
    def event_label(alert_id: str) -> str:
        return "opspilot-id-" + evidence_hash(alert_id)[:24]

    def find_existing(self, alert_id: str) -> DeliveryOutcome | None:
        label = self.event_label(alert_id)
        jql = f'project = "{self.project_key}" AND labels = "{label}" ORDER BY created DESC'
        with httpx.Client(
            timeout=self.timeout_seconds,
            auth=self.auth,
            headers=self.headers,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            response = client.get(
                f"{self.base_url}/rest/api/3/search/jql",
                params={"jql": jql, "maxResults": 1, "fields": "key"},
            )
        if response.status_code != 200:
            detail, _ = redact_text(response.text, max_chars=500)
            raise IntegrationError(f"Jira search failed HTTP {response.status_code}: {detail}")
        try:
            issues = response.json().get("issues", [])
        except (json.JSONDecodeError, AttributeError) as error:
            raise IntegrationError("Jira search returned invalid JSON") from error
        if not issues:
            return None
        key = str(issues[0]["key"])
        return DeliveryOutcome(
            state="sent",
            external_id=key,
            external_url=f"{self.base_url}/browse/{quote(key, safe='-')}",
            response_sha256=evidence_hash(issues[0]),
        )

    def create_or_find(
        self,
        alert: AlertEvent,
        rca: RootCauseAnalysis,
        *,
        evidence_sha256: str,
        prompt_version: str,
        model: str,
    ) -> DeliveryOutcome:
        existing = self.find_existing(alert.alert_id)
        if existing:
            return existing
        label = self.event_label(alert.alert_id)
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "issuetype": {"name": self.issue_type},
                "summary": (
                    f"[{alert.severity}] {rca.summary.headline} - {alert.node}/{alert.resource}"
                )[:255],
                "description": rca_adf_document(
                    alert,
                    rca,
                    evidence_sha256=evidence_sha256,
                    prompt_version=prompt_version,
                    model=model,
                ),
                "labels": ["opspilot", label, f"opspilot-{alert.kind.value}"[:255]],
            },
        }
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                auth=self.auth,
                headers=self.headers,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = client.post(f"{self.base_url}/rest/api/3/issue", json=payload)
        except (httpx.TimeoutException, httpx.NetworkError) as error:
            # Outcome may be committed remotely. Resolve by the unique event label.
            try:
                found = self.find_existing(alert.alert_id)
            except IntegrationError:
                found = None
            if found:
                return found
            raise IntegrationError(
                f"Jira create outcome is unknown after {type(error).__name__}",
                outcome_unknown=True,
            ) from error
        if response.status_code not in {200, 201}:
            detail, _ = redact_text(response.text, max_chars=1000)
            raise IntegrationError(f"Jira create failed HTTP {response.status_code}: {detail}")
        try:
            body = response.json()
            key = str(body["key"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise IntegrationError(
                "Jira create returned invalid JSON", outcome_unknown=True
            ) from error
        return DeliveryOutcome(
            state="sent",
            external_id=key,
            external_url=f"{self.base_url}/browse/{quote(key, safe='-')}",
            response_sha256=evidence_hash(body),
        )

    def add_rca_comment(
        self,
        issue_key: str,
        alert: AlertEvent,
        rca: RootCauseAnalysis,
        *,
        evidence_sha256: str,
        prompt_version: str,
        model: str,
    ) -> DeliveryOutcome:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]+-\d+", issue_key):
            raise ValueError("invalid Jira issue key")
        payload = {
            "body": rca_adf_document(
                alert,
                rca,
                evidence_sha256=evidence_sha256,
                prompt_version=prompt_version,
                model=model,
            )
        }
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                auth=self.auth,
                headers=self.headers,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = client.post(
                    f"{self.base_url}/rest/api/3/issue/{quote(issue_key, safe='-')}/comment",
                    json=payload,
                )
        except (httpx.TimeoutException, httpx.NetworkError) as error:
            raise IntegrationError(
                f"Jira comment outcome is unknown after {type(error).__name__}",
                outcome_unknown=True,
            ) from error
        if response.status_code not in {200, 201}:
            detail, _ = redact_text(response.text, max_chars=1000)
            raise IntegrationError(f"Jira comment failed HTTP {response.status_code}: {detail}")
        body = response.json()
        return DeliveryOutcome(
            state="sent",
            external_id=str(body.get("id") or ""),
            external_url=f"{self.base_url}/browse/{quote(issue_key, safe='-')}",
            response_sha256=evidence_hash(body),
        )


class SlackWebhookClient:
    def __init__(
        self,
        webhook_url: SecretStr,
        *,
        timeout_seconds: float = 10,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    def post(self, payload: dict[str, Any]) -> DeliveryOutcome:
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = client.post(self.webhook_url.get_secret_value(), json=payload)
        except (httpx.TimeoutException, httpx.NetworkError) as error:
            raise IntegrationError(
                f"Slack webhook outcome is unknown after {type(error).__name__}",
                outcome_unknown=True,
            ) from error
        if response.status_code != 200 or response.text.strip().lower() != "ok":
            detail, _ = redact_text(response.text, max_chars=500)
            raise IntegrationError(f"Slack webhook failed HTTP {response.status_code}: {detail}")
        return DeliveryOutcome(
            state="sent",
            external_id=None,
            external_url=None,
            response_sha256=evidence_hash({"status": response.status_code, "body": "ok"}),
        )
