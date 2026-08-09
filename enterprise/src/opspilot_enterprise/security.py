"""Redaction, integrity, request authentication, and safe URL helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:br|sk|xox[baprs])-[A-Za-z0-9_.-]{8,}\b"),
    re.compile(
        r"(?i)((?:--(?:api[-_]?key|apikey|authorization|bearer[-_]?token|"
        r"client[-_]?secret|password|passwd|secret|token|access[-_]?token|"
        r"refresh[-_]?token|ws[-_]?auth|ws[-_]?token|ws[-_]?token[-_]?sha256))"
        r"(?:\s+|=))([^\s'\"]+)"
    ),
    re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+|basic\s+)?([^\s,;]+)"),
    re.compile(
        r"(?i)((?:api[_-]?key|token|password|passwd|secret|client_secret)\s*[:=]\s*)"
        r"([^\s,;]+)"
    ),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.S),
)
SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "token",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "access_token",
    "refresh_token",
}
SENSITIVE_CLI_FLAGS = {
    "--api-key",
    "--apikey",
    "--authorization",
    "--bearer-token",
    "--client-secret",
    "--password",
    "--passwd",
    "--secret",
    "--token",
    "--access-token",
    "--refresh-token",
    "--ws-auth",
    "--ws-token",
    "--ws-token-sha256",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def evidence_hash(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def redact_text(value: str, *, max_chars: int = 100_000) -> tuple[str, bool]:
    """Return redacted text and whether a length cap was applied."""

    cleaned = value.replace("\x00", "�")
    for pattern in REDACTION_PATTERNS:
        if pattern.groups:
            cleaned = pattern.sub(r"\1[REDACTED]", cleaned)
        else:
            cleaned = pattern.sub("[REDACTED]", cleaned)
    truncated = len(cleaned) > max_chars
    if truncated:
        head = max_chars // 3
        tail = max_chars - head
        cleaned = f"{cleaned[:head]}\n[...TRUNCATED...]\n{cleaned[-tail:]}"
    return cleaned, truncated


def redact_url(value: str) -> str:
    parts = urlsplit(value)
    query = []
    for key, item in parse_qsl(parts.query, keep_blank_values=True):
        query.append((key, "[REDACTED]" if key.lower() in SENSITIVE_KEYS else item))
    hostname = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{hostname}{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), ""))


def redact_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 20:
        return "[DEPTH-LIMIT]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS:
                result[key_text] = "[REDACTED]"
            else:
                result[key_text] = redact_json(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [redact_json(item, depth=depth + 1) for item in value[:10_000]]
    if isinstance(value, str):
        return redact_text(value)[0]
    return value


def redact_argv(argv: list[str]) -> list[str]:
    """Redact both `--secret=value` and `--secret value` argument forms."""

    result: list[str] = []
    redact_next = False
    for raw in argv:
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        flag, separator, _ = raw.partition("=")
        normalized = flag.lower().replace("_", "-")
        if normalized in SENSITIVE_CLI_FLAGS:
            if separator:
                result.append(f"{flag}=[REDACTED]")
            else:
                result.append(raw)
                redact_next = True
            continue
        result.append(redact_text(raw, max_chars=4096)[0])
    return result


def sign_hmac(secret: str, timestamp: int, body: bytes) -> str:
    payload = f"v1:{timestamp}:".encode() + body
    return "v1=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def verify_hmac_request(
    body: bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    now: int | None = None,
    replay_seconds: int = 300,
) -> bool:
    normalized = {key.lower(): value for key, value in headers.items()}
    raw_timestamp = normalized.get("x-opspilot-timestamp", "")
    received = normalized.get("x-opspilot-signature", "")
    try:
        timestamp = int(raw_timestamp)
    except ValueError:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > replay_seconds:
        return False
    expected = sign_hmac(secret, timestamp, body)
    return hmac.compare_digest(expected, received)


def approval_token(
    secret: str,
    *,
    alert_id: str,
    runbook_id: str,
    approved_by: str,
    expires_at: int,
) -> str:
    message = f"{alert_id}\n{runbook_id}\n{approved_by}\n{expires_at}".encode()
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"v1.{expires_at}.{digest}"


def verify_approval_token(
    token: str,
    secret: str,
    *,
    alert_id: str,
    runbook_id: str,
    approved_by: str,
    now: int | None = None,
) -> bool:
    try:
        version, expires_text, _ = token.split(".", 2)
        expires_at = int(expires_text)
    except (ValueError, TypeError):
        return False
    if version != "v1" or expires_at < (int(time.time()) if now is None else now):
        return False
    expected = approval_token(
        secret,
        alert_id=alert_id,
        runbook_id=runbook_id,
        approved_by=approved_by,
        expires_at=expires_at,
    )
    return hmac.compare_digest(expected, token)
