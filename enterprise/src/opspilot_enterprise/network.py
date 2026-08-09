"""Network-device REST adapter and hardware-level interface flapping ingestion.

`BharatRouter` is intentionally not implemented here: BharatRouter is an AI
inference gateway, not a hardware router API. This adapter is vendor-neutral and
the endpoint path/auth header are configuration. Replace only the parser when a
real network vendor contract is available.
"""

from __future__ import annotations

import email.utils
import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx
from pydantic import SecretStr

from .ledger import IncidentLedger
from .models import (
    AlertEvent,
    AlertKind,
    AlertState,
    FlapAssessment,
    InterfaceCounters,
    NetworkInterface,
    NetworkSnapshot,
)
from .security import evidence_hash, redact_json, redact_text


class RouterApiError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


def _retry_after(value: str | None, *, maximum: float = 30) -> float | None:
    if not value:
        return None
    try:
        return min(maximum, max(0, float(value)))
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
            return min(maximum, max(0, (when - datetime.now(UTC)).total_seconds()))
        except (TypeError, ValueError):
            return None


def _state(value: Any, *, oper: bool = False) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in {"up", "1", "true", "enabled", "connected", "link-up"}:
        return "up"
    if normalized in {"down", "0", "false", "disabled", "notconnect", "link-down"}:
        return "down"
    if oper and normalized in {"degraded", "lowerlayerdown", "testing", "dormant"}:
        return "degraded"
    return "unknown"


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _first(mapping: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), UTC)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
    except (ValueError, TypeError, OSError):
        return None


def parse_interface_snapshot(
    payload: Any,
    *,
    device_id: str,
    vendor: str = "generic-rest",
    collected_at: datetime | None = None,
) -> NetworkSnapshot:
    """Normalize common REST/SNMP-proxy field shapes into one evidence contract."""

    if isinstance(payload, list):
        raw_interfaces = payload
    elif isinstance(payload, dict):
        raw_interfaces = _first(payload, "interfaces", "items", "ports", default=None)
        if raw_interfaces is None and isinstance(payload.get("data"), dict):
            raw_interfaces = _first(payload["data"], "interfaces", "items", "ports", default=[])
        elif raw_interfaces is None:
            raw_interfaces = payload.get("data", [])
    else:
        raise RouterApiError("router response must be a JSON object or array")
    if not isinstance(raw_interfaces, list):
        raise RouterApiError("router response does not contain an interface array")

    interfaces: list[NetworkInterface] = []
    warnings: list[str] = []
    for index, raw in enumerate(raw_interfaces):
        if not isinstance(raw, dict):
            warnings.append(f"interface[{index}] ignored: not an object")
            continue
        name = str(_first(raw, "name", "ifName", "interface", "port", "id", default="")).strip()
        if not name:
            warnings.append(f"interface[{index}] ignored: missing name")
            continue
        counters_raw = raw.get("counters") if isinstance(raw.get("counters"), dict) else raw
        assert isinstance(counters_raw, dict)
        counters = InterfaceCounters(
            rx_bytes=_integer(_first(counters_raw, "rx_bytes", "inOctets", "ifInOctets")),
            tx_bytes=_integer(_first(counters_raw, "tx_bytes", "outOctets", "ifOutOctets")),
            rx_packets=_integer(_first(counters_raw, "rx_packets", "inPackets", "ifInUcastPkts")),
            tx_packets=_integer(_first(counters_raw, "tx_packets", "outPackets", "ifOutUcastPkts")),
            rx_errors=_integer(_first(counters_raw, "rx_errors", "inErrors", "ifInErrors")),
            tx_errors=_integer(_first(counters_raw, "tx_errors", "outErrors", "ifOutErrors")),
            rx_drops=_integer(_first(counters_raw, "rx_drops", "inDiscards", "ifInDiscards")),
            tx_drops=_integer(_first(counters_raw, "tx_drops", "outDiscards", "ifOutDiscards")),
        )
        known = {
            "name",
            "ifName",
            "interface",
            "port",
            "id",
            "description",
            "ifAlias",
            "admin_status",
            "adminStatus",
            "ifAdminStatus",
            "oper_status",
            "operStatus",
            "ifOperStatus",
            "status",
            "speed_bps",
            "speed",
            "ifSpeed",
            "mtu",
            "ifMtu",
            "mac_address",
            "mac",
            "ifPhysAddress",
            "ipv4_addresses",
            "ipv4",
            "ipv6_addresses",
            "ipv6",
            "last_changed_at",
            "lastChange",
            "last_changed",
            "counters",
        }
        vendor_fields = {key: value for key, value in raw.items() if key not in known}
        sanitized_vendor = redact_json(vendor_fields)
        interfaces.append(
            NetworkInterface(
                device_id=device_id,
                name=name[:253],
                description=str(_first(raw, "description", "ifAlias", default=""))[:1024],
                admin_status=_state(_first(raw, "admin_status", "adminStatus", "ifAdminStatus")),  # type: ignore[arg-type]
                oper_status=_state(
                    _first(raw, "oper_status", "operStatus", "ifOperStatus", "status"),
                    oper=True,
                ),  # type: ignore[arg-type]
                speed_bps=(_integer(_first(raw, "speed_bps", "speed", "ifSpeed")) or None),
                mtu=_integer(_first(raw, "mtu", "ifMtu")) or None,
                mac_address=(
                    str(_first(raw, "mac_address", "mac", "ifPhysAddress"))[:64]
                    if _first(raw, "mac_address", "mac", "ifPhysAddress")
                    else None
                ),
                ipv4_addresses=[
                    str(item)[:128]
                    for item in (_first(raw, "ipv4_addresses", "ipv4", default=[]) or [])
                ],
                ipv6_addresses=[
                    str(item)[:128]
                    for item in (_first(raw, "ipv6_addresses", "ipv6", default=[]) or [])
                ],
                counters=counters,
                last_changed_at=_parse_timestamp(
                    _first(raw, "last_changed_at", "lastChange", "last_changed")
                ),
                vendor_fields=(sanitized_vendor if isinstance(sanitized_vendor, dict) else {}),
            )
        )
    if not interfaces:
        raise RouterApiError("router response contained no valid interfaces")
    sanitized_payload = redact_json(payload)
    return NetworkSnapshot(
        device_id=device_id,
        vendor=vendor,
        collected_at=collected_at or datetime.now(UTC),
        interfaces=interfaces,
        source_sha256=evidence_hash(sanitized_payload),
        warnings=warnings,
    )


class RouterTelemetryClient:
    """API-key-authenticated, read-only REST client for a real router controller."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: SecretStr,
        auth_header: str = "X-API-Key",
        interfaces_path: str = "/v1/devices/{device_id}/interfaces",
        timeout_seconds: float = 10,
        max_attempts: int = 3,
        vendor: str = "generic-rest",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("router base URL must be absolute")
        if "{device_id}" not in interfaces_path:
            raise ValueError("router interface path must contain {device_id}")
        if not auth_header or "\n" in auth_header or "\r" in auth_header:
            raise ValueError("invalid router authentication header")
        self.base_url = base_url.rstrip("/") + "/"
        self.api_key = api_key
        self.auth_header = auth_header
        self.interfaces_path = interfaces_path
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.vendor = vendor
        self.transport = transport

    def fetch_interfaces(self, device_id: str) -> NetworkSnapshot:
        encoded_id = quote(device_id, safe="")
        path = self.interfaces_path.format(device_id=encoded_id).lstrip("/")
        url = urljoin(self.base_url, path)
        headers = {"Accept": "application/json", self.auth_header: self.api_key.get_secret_value()}
        last_error: Exception | None = None
        with httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            for attempt in range(1, self.max_attempts + 1):
                try:
                    response = client.get(url, headers=headers)
                    if response.status_code == 200:
                        try:
                            payload = response.json()
                        except json.JSONDecodeError as error:
                            raise RouterApiError("router returned invalid JSON") from error
                        return parse_interface_snapshot(
                            payload, device_id=device_id, vendor=self.vendor
                        )
                    retryable = response.status_code in {408, 425, 429, 500, 502, 503, 504}
                    detail, _ = redact_text(response.text, max_chars=500)
                    last_error = RouterApiError(
                        f"router API returned HTTP {response.status_code}: {detail}",
                        status_code=response.status_code,
                        retryable=retryable,
                    )
                    if not retryable or attempt == self.max_attempts:
                        raise last_error
                    delay = _retry_after(response.headers.get("retry-after"))
                except (httpx.TimeoutException, httpx.NetworkError) as error:
                    last_error = RouterApiError(
                        f"router API transport failure: {type(error).__name__}", retryable=True
                    )
                    if attempt == self.max_attempts:
                        raise last_error from error
                    delay = None
                time.sleep(
                    delay
                    if delay is not None
                    else min(5, (2 ** (attempt - 1)) + secrets.randbelow(1000) / 1000)
                )
        raise RouterApiError(f"router API failed: {last_error}", retryable=True)


class HardwareFlapDetector:
    """Turn observed link-state changes into temporal-ledger transitions."""

    def __init__(
        self,
        ledger: IncidentLedger,
        *,
        window_days: int = 7,
        cycle_threshold: int = 5,
    ) -> None:
        self.ledger = ledger
        self.window_days = window_days
        self.cycle_threshold = cycle_threshold

    def ingest(
        self, snapshot: NetworkSnapshot
    ) -> tuple[list[AlertEvent], dict[str, FlapAssessment]]:
        generated: list[AlertEvent] = []
        assessments: dict[str, FlapAssessment] = {}
        for interface in snapshot.interfaces:
            previous = self.ledger.latest_interface_sample(snapshot.device_id, interface.name)
            sample_payload = interface.model_dump(mode="json")
            self.ledger.record_interface_sample(
                device_id=snapshot.device_id,
                interface_name=interface.name,
                admin_status=interface.admin_status,
                oper_status=interface.oper_status,
                counters=interface.counters.model_dump(),
                sample_sha256=evidence_hash(sample_payload),
                collected_at=snapshot.collected_at,
            )
            previous_status = str(previous["oper_status"]) if previous else None
            if interface.oper_status not in {"up", "down"}:
                continue
            if previous_status == interface.oper_status:
                resource_key = (
                    f"router_interface:{snapshot.device_id}:{interface.name}:oper_status".lower()
                )
                assessments[interface.name] = self.ledger.flap_assessment(
                    resource_key,
                    window_days=self.window_days,
                    threshold_cycles=self.cycle_threshold,
                )
                continue
            transition_key = evidence_hash(
                {
                    "device": snapshot.device_id,
                    "interface": interface.name,
                    "status": interface.oper_status,
                    "time": snapshot.collected_at.isoformat(),
                }
            )[:20]
            alert = AlertEvent(
                alert_id=f"router-{transition_key}",
                kind=AlertKind.ROUTER_INTERFACE,
                state=(
                    AlertState.FIRING if interface.oper_status == "down" else AlertState.RESOLVED
                ),
                source="router-poller",
                node=snapshot.device_id,
                resource=interface.name,
                metric="oper_status",
                severity="SEV-2" if interface.oper_status == "down" else "SEV-4",
                observed_value=interface.oper_status,
                threshold="up",
                occurred_at=snapshot.collected_at,
                labels={"vendor": snapshot.vendor, "admin_status": interface.admin_status},
                annotations={
                    "description": interface.description,
                    "counter_sha256": evidence_hash(interface.counters.model_dump()),
                },
            )
            self.ledger.register_alert(alert)
            generated.append(alert)
            assessments[interface.name] = self.ledger.flap_assessment(
                alert.resource_key,
                window_days=self.window_days,
                threshold_cycles=self.cycle_threshold,
            )
        return generated, assessments
