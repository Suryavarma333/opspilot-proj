from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import SecretStr

from opspilot_enterprise.ledger import IncidentLedger
from opspilot_enterprise.network import (
    HardwareFlapDetector,
    RouterTelemetryClient,
    parse_interface_snapshot,
)

ROUTER_RESPONSE = {
    "data": {
        "interfaces": [
            {
                "ifName": "Gi0/1",
                "ifAlias": "ISP uplink",
                "ifAdminStatus": "up",
                "ifOperStatus": "down",
                "ifSpeed": 1_000_000_000,
                "ifMtu": 1500,
                "ifInOctets": 1000,
                "ifOutOctets": 2000,
                "ifInErrors": 3,
                "ifOutErrors": 4,
                "ifInDiscards": 5,
                "ifOutDiscards": 6,
                "vendorSecret": "api_key=hidden-value",
            }
        ]
    }
}


def test_router_parser_normalizes_interface_and_counters() -> None:
    snapshot = parse_interface_snapshot(ROUTER_RESPONSE, device_id="edge-01")
    interface = snapshot.interfaces[0]
    assert interface.name == "Gi0/1"
    assert interface.admin_status == "up"
    assert interface.oper_status == "down"
    assert interface.counters.rx_errors == 3
    assert interface.counters.tx_drops == 6
    assert "hidden-value" not in json.dumps(interface.vendor_fields)


def test_router_client_sends_configured_api_key_header() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/devices/edge-01/interfaces"
        assert request.headers["X-API-Key"] == "router-secret"
        return httpx.Response(200, json=ROUTER_RESPONSE)

    client = RouterTelemetryClient(
        base_url="https://router-controller.example",
        api_key=SecretStr("router-secret"),
        transport=httpx.MockTransport(handler),
    )
    assert client.fetch_interfaces("edge-01").interfaces[0].name == "Gi0/1"


def test_hardware_detector_records_link_state_changes(tmp_path: Path) -> None:
    ledger = IncidentLedger(tmp_path / "ledger.sqlite3")
    detector = HardwareFlapDetector(ledger, cycle_threshold=2)
    down = parse_interface_snapshot(
        ROUTER_RESPONSE,
        device_id="edge-01",
        collected_at=datetime(2026, 8, 5, 1, 0, tzinfo=UTC),
    )
    first_alerts, _ = detector.ingest(down)
    assert first_alerts[0].state == "firing"

    up_payload = json.loads(json.dumps(ROUTER_RESPONSE))
    up_payload["data"]["interfaces"][0]["ifOperStatus"] = "up"
    up = parse_interface_snapshot(
        up_payload,
        device_id="edge-01",
        collected_at=datetime(2026, 8, 5, 1, 5, tzinfo=UTC),
    )
    second_alerts, assessments = detector.ingest(up)
    assert second_alerts[0].state == "resolved"
    assert assessments["Gi0/1"].complete_cycles == 1
