from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from opspilot_enterprise.devices import (
    CredentialCipher,
    DeviceCreate,
    DevicePollTarget,
    NetworkDeviceStore,
)
from opspilot_enterprise.ledger import IncidentLedger
from opspilot_enterprise.snmp_worker import SnmpMetrics, SnmpPollingWorker, poll_device


@pytest.mark.asyncio
async def test_poll_device_keeps_icmp_and_snmp_status_separate(monkeypatch) -> None:
    async def fake_ping(_hostname: str, _timeout: float):
        return False, None, "ICMP blocked"

    async def fake_snmp(_target, *, timeout_seconds: float, retries: int):
        assert timeout_seconds == 2
        assert retries == 1
        return SnmpMetrics(
            sys_name="edge-01",
            sys_description="Test router",
            sys_object_id="1.3.6.1.4.1.9",
            uptime_seconds=86400,
            interface_total=4,
            interface_up=3,
            interface_down=1,
            interface_unknown=0,
        )

    monkeypatch.setattr("opspilot_enterprise.snmp_worker.poll_icmp", fake_ping)
    monkeypatch.setattr("opspilot_enterprise.snmp_worker.poll_snmp", fake_snmp)
    result = await poll_device(
        DevicePollTarget(
            id="device-1",
            hostname="192.0.2.10",
            snmp_port=161,
            snmp_version="v2c",
            credentials={"community": "secret"},
        ),
        icmp_timeout_seconds=2,
        snmp_timeout_seconds=2,
        snmp_retries=1,
    )
    assert result.status == "DOWN"
    assert result.snmp_status == "UP"
    assert result.interface_up == 3
    assert result.error == "ICMP blocked"


@pytest.mark.asyncio
async def test_worker_reads_and_updates_same_sqlite_database(tmp_path: Path, monkeypatch) -> None:
    ledger = IncidentLedger(tmp_path / "state.sqlite3")
    store = NetworkDeviceStore(
        ledger,
        CredentialCipher(SecretStr(Fernet.generate_key().decode("ascii"))),
    )
    created = store.create_device(
        DeviceCreate(
            hostname="192.0.2.55",
            device_name="Distribution Switch",
            snmp_version="v2c",
            community=SecretStr("readonly"),
        )
    )

    async def fake_poll(_target, **_options):
        from opspilot_enterprise.devices import DevicePollResult

        return DevicePollResult(
            status="UP",
            ping_latency_ms=1.25,
            snmp_status="UP",
            sys_name="dist-01",
            uptime_seconds=7200,
            interface_total=24,
            interface_up=23,
            interface_down=1,
            interface_unknown=0,
        )

    monkeypatch.setattr("opspilot_enterprise.snmp_worker.poll_device", fake_poll)
    count = await SnmpPollingWorker(store=store).run_once()
    assert count == 1
    updated = store.get_device(created.id)
    assert updated is not None
    assert updated.status == "UP"
    assert updated.snmp_status == "UP"
    assert updated.sys_name == "dist-01"
    assert updated.interface_total == 24
