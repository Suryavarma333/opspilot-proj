from __future__ import annotations

import gzip
import json
from pathlib import Path

from opspilot_enterprise.evidence import EvidenceStore
from opspilot_enterprise.security import (
    approval_token,
    redact_argv,
    redact_json,
    redact_text,
    sign_hmac,
    verify_approval_token,
    verify_hmac_request,
)


def test_redaction_removes_common_secrets() -> None:
    text = (
        "Authorization: Bearer br-secret-token api_key=abcdef123456 "
        "password=hunter2 xoxb-123456789-secret"
    )
    cleaned, _ = redact_text(text)
    assert "br-secret-token" not in cleaned
    assert "abcdef123456" not in cleaned
    assert "hunter2" not in cleaned
    assert "xoxb-" not in cleaned
    assert cleaned.count("[REDACTED]") >= 3


def test_recursive_json_redaction() -> None:
    result = redact_json({"token": "secret", "nested": {"password": "bad", "safe": "visible"}})
    assert result == {
        "token": "[REDACTED]",
        "nested": {"password": "[REDACTED]", "safe": "visible"},
    }


def test_argv_redaction_handles_separate_and_equals_values() -> None:
    assert redact_argv(
        [
            "/usr/bin/program",
            "--api-key",
            "secret-one",
            "--password=secret-two",
            "--cpu",
            "4",
        ]
    ) == [
        "/usr/bin/program",
        "--api-key",
        "[REDACTED]",
        "--password=[REDACTED]",
        "--cpu",
        "4",
    ]
    embedded, _ = redact_text("python tool.py --token secret-three --cpu 4")
    assert "secret-three" not in embedded


def test_hmac_authentication_and_replay_window() -> None:
    body = b'{"alert":"x"}'
    timestamp = 1_725_000_000
    signature = sign_hmac("webhook-secret", timestamp, body)
    headers = {
        "X-OpsPilot-Timestamp": str(timestamp),
        "X-OpsPilot-Signature": signature,
    }
    assert verify_hmac_request(body, headers, "webhook-secret", now=timestamp + 10)
    assert not verify_hmac_request(body, headers, "wrong", now=timestamp + 10)
    assert not verify_hmac_request(body, headers, "webhook-secret", now=timestamp + 301)


def test_approval_token_is_bound_to_actor_alert_and_runbook() -> None:
    token = approval_token(
        "approval-secret",
        alert_id="alert-0001",
        runbook_id="restart.allowed_service",
        approved_by="alice@example.com",
        expires_at=2_000_000_000,
    )
    assert verify_approval_token(
        token,
        "approval-secret",
        alert_id="alert-0001",
        runbook_id="restart.allowed_service",
        approved_by="alice@example.com",
        now=1_999_999_000,
    )
    assert not verify_approval_token(
        token,
        "approval-secret",
        alert_id="alert-0002",
        runbook_id="restart.allowed_service",
        approved_by="alice@example.com",
        now=1_999_999_000,
    )


def test_evidence_store_is_content_addressed_and_idempotent(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence")
    first = store.write("cpu-alert-0001", {"api_key": "secret", "value": 42})
    second = store.write("cpu-alert-0001", {"api_key": "different", "value": 42})
    assert first.path == second.path
    assert first.sha256 == second.sha256
    with gzip.open(first.path, "rt", encoding="utf-8") as handle:
        stored = json.load(handle)
    assert stored == {"api_key": "[REDACTED]", "value": 42}
