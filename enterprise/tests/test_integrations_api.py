from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from pydantic import SecretStr

from opspilot_enterprise.api import create_app
from opspilot_enterprise.config import Settings
from opspilot_enterprise.integrations import (
    JiraClient,
    SlackWebhookClient,
    rca_adf_document,
    slack_webhook_payload,
)
from opspilot_enterprise.llm import deterministic_fallback
from opspilot_enterprise.security import sign_hmac


def test_jira_search_before_create_and_payload(cpu_alert, empty_history) -> None:
    rca = deterministic_fallback(cpu_alert, empty_history, None, reason="fixture")
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"issues": []})
        payload = json.loads(request.content)
        assert payload["fields"]["project"]["key"] == "CORE"
        assert "opspilot" in payload["fields"]["labels"]
        return httpx.Response(201, json={"id": "10001", "key": "CORE-101"})

    jira = JiraClient(
        base_url="https://example.atlassian.net",
        project_key="CORE",
        user_email="sre@example.com",
        api_token=SecretStr("jira-token"),
        transport=httpx.MockTransport(handler),
    )
    outcome = jira.create_or_find(
        cpu_alert,
        rca,
        evidence_sha256="c" * 64,
        prompt_version="test-prompt",
        model="test-model",
    )
    assert [item.method for item in requests] == ["GET", "POST"]
    assert outcome.external_id == "CORE-101"


def test_jira_and_slack_render_all_four_parts(cpu_alert, empty_history) -> None:
    rca = deterministic_fallback(cpu_alert, empty_history, None, reason="fixture")
    adf = rca_adf_document(
        cpu_alert, rca, evidence_sha256="d" * 64, prompt_version="v2", model="model"
    )
    headings = [
        block["content"][0]["text"] for block in adf["content"] if block["type"] == "heading"
    ]
    assert {"1. Summary", "2. Evidence", "3. History", "4. Resolution"}.issubset(headings)
    slack = slack_webhook_payload(
        cpu_alert,
        rca,
        evidence_sha256="d" * 64,
        jira_key="CORE-101",
        jira_url="https://example.atlassian.net/browse/CORE-101",
    )
    rendered = json.dumps(slack)
    for section in ("1. Summary", "2. Evidence", "3. History", "4. Resolution"):
        assert section in rendered


def test_slack_webhook_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "hooks.slack.com"
        return httpx.Response(200, text="ok")

    slack = SlackWebhookClient(
        SecretStr("https://hooks.slack.com/services/T/B/X"),
        transport=httpx.MockTransport(handler),
    )
    assert slack.post({"text": "hello"}).state == "sent"


def test_signed_alert_api_is_idempotent(tmp_path: Path, cpu_alert) -> None:
    settings = Settings(
        environment="test",
        state_db=tmp_path / "api.sqlite3",
        evidence_dir=tmp_path / "evidence",
        webhook_hmac_secret=SecretStr("webhook-secret"),
        approval_hmac_secret=SecretStr("approval-secret"),
        allow_insecure_http=True,
    )
    client = TestClient(create_app(settings))
    body = cpu_alert.model_dump_json().encode()
    timestamp = int(time.time())
    headers = {
        "X-OpsPilot-Timestamp": str(timestamp),
        "X-OpsPilot-Signature": sign_hmac("webhook-secret", timestamp, body),
        "Content-Type": "application/json",
    }
    first = client.post("/v1/alerts", content=body, headers=headers)
    second = client.post("/v1/alerts", content=body, headers=headers)
    assert first.status_code == 202
    assert first.json()["new_incident"] is True
    assert second.json()["new_incident"] is False
    assert second.json()["duplicate_occurrence"] is True


def test_unsigned_alert_is_rejected(tmp_path: Path, cpu_alert) -> None:
    settings = Settings(
        environment="test",
        state_db=tmp_path / "api.sqlite3",
        evidence_dir=tmp_path / "evidence",
        webhook_hmac_secret=SecretStr("webhook-secret"),
        approval_hmac_secret=SecretStr("approval-secret"),
        allow_insecure_http=True,
    )
    client = TestClient(create_app(settings))
    assert client.post("/v1/alerts", json=cpu_alert.model_dump(mode="json")).status_code == 401
