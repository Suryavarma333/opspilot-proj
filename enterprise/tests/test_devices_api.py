from __future__ import annotations

import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import SecretStr

from opspilot_enterprise.api import create_app
from opspilot_enterprise.config import Settings


def settings_for(tmp_path: Path, *, with_snmp_key: bool = True) -> Settings:
    return Settings(
        environment="test",
        state_db=tmp_path / "api.sqlite3",
        evidence_dir=tmp_path / "evidence",
        webhook_hmac_secret=SecretStr("webhook-secret"),
        approval_hmac_secret=SecretStr("approval-secret"),
        snmp_credential_key=(
            SecretStr(Fernet.generate_key().decode("ascii")) if with_snmp_key else None
        ),
        allow_insecure_http=True,
    )


def test_device_crud_encrypts_and_never_returns_community(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    client = TestClient(create_app(settings))
    payload = {
        "hostname": "192.0.2.10",
        "device_name": "Core Switch 01",
        "snmp_version": "v2c",
        "snmp_port": 161,
        "community": "read-only-secret",
    }

    created_response = client.post("/api/devices", json=payload)
    assert created_response.status_code == 201
    created = created_response.json()
    assert created["hostname"] == "192.0.2.10"
    assert created["credentials_configured"] is True
    assert "community" not in created

    with sqlite3.connect(settings.state_db) as connection:
        encrypted = connection.execute(
            "SELECT credentials_encrypted FROM network_devices WHERE id=?", (created["id"],)
        ).fetchone()[0]
    assert isinstance(encrypted, bytes)
    assert b"read-only-secret" not in encrypted

    listed = client.get("/api/devices")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert "read-only-secret" not in listed.text

    duplicate = client.post("/api/devices", json=payload)
    assert duplicate.status_code == 409

    paused = client.patch(f"/api/devices/{created['id']}", json={"enabled": False})
    assert paused.status_code == 200
    assert paused.json()["enabled"] is False
    assert paused.json()["status"] == "UNKNOWN"

    deleted = client.delete(f"/api/devices/{created['id']}")
    assert deleted.status_code == 204
    assert client.get("/api/devices").json()["total"] == 0


def test_device_create_requires_server_credential_key(tmp_path: Path) -> None:
    client = TestClient(create_app(settings_for(tmp_path, with_snmp_key=False)))
    response = client.post(
        "/api/devices",
        json={
            "hostname": "switch.example.test",
            "device_name": "Access Switch",
            "snmp_version": "v2c",
            "community": "monitoring",
        },
    )
    assert response.status_code == 503


def test_snmpv3_uses_usm_credentials_not_community(tmp_path: Path) -> None:
    client = TestClient(create_app(settings_for(tmp_path)))
    valid = client.post(
        "/api/devices",
        json={
            "hostname": "2001:db8::10",
            "device_name": "IPv6 Core Router",
            "snmp_version": "v3",
            "snmpv3_username": "opspilot-monitor",
            "snmpv3_security_level": "authPriv",
            "snmpv3_auth_protocol": "SHA256",
            "snmpv3_auth_password": "auth-password",
            "snmpv3_priv_protocol": "AES128",
            "snmpv3_priv_password": "privacy-password",
        },
    )
    assert valid.status_code == 201
    assert valid.json()["snmp_security_level"] == "authPriv"

    invalid = client.post(
        "/api/devices",
        json={
            "hostname": "192.0.2.44",
            "device_name": "Invalid v3 Router",
            "snmp_version": "v3",
            "community": "not-valid-for-v3",
            "snmpv3_username": "monitor",
        },
    )
    assert invalid.status_code == 422
    assert "community string" in invalid.text
