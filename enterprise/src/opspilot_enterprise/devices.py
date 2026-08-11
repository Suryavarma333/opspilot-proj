"""Validated network-device inventory and encrypted SNMP credential storage."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .ledger import IncidentLedger, _iso

SnmpVersion = Literal["v2c", "v3"]
SnmpSecurityLevel = Literal["community", "noAuthNoPriv", "authNoPriv", "authPriv"]
SnmpAuthProtocol = Literal["SHA", "SHA224", "SHA256", "SHA384", "SHA512"]
SnmpPrivacyProtocol = Literal["AES128", "AES192", "AES256"]
DeviceStatus = Literal["UNKNOWN", "UP", "DOWN"]

_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SNMPV3_USER = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


class DuplicateDeviceError(ValueError):
    pass


class DeviceNotFoundError(LookupError):
    pass


class CredentialsUnavailableError(RuntimeError):
    pass


class CredentialDecryptionError(RuntimeError):
    pass


def normalize_hostname(value: str) -> str:
    """Accept IP literals or conservative DNS hostnames and reject CLI options."""

    candidate = value.strip()
    if not candidate or len(candidate) > 253 or candidate.startswith("-"):
        raise ValueError("hostname must be a valid IP address or DNS hostname")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        normalized = candidate.rstrip(".").lower()
        if not normalized or any(
            not _DNS_LABEL.fullmatch(label) for label in normalized.split(".")
        ):
            raise ValueError("hostname must be a valid IP address or DNS hostname") from None
        return normalized


def _secret_value(secret: SecretStr | None) -> str | None:
    return secret.get_secret_value() if secret else None


def _valid_secret(value: str | None, *, minimum: int, maximum: int) -> bool:
    return bool(
        value
        and minimum <= len(value) <= maximum
        and all(character.isprintable() and character not in "\r\n" for character in value)
    )


class DeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=253)
    device_name: str = Field(min_length=1, max_length=128)
    snmp_version: SnmpVersion
    snmp_port: int = Field(default=161, ge=1, le=65535)
    community: SecretStr | None = None
    snmpv3_username: str | None = Field(default=None, max_length=64)
    snmpv3_security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "authPriv"
    snmpv3_auth_protocol: SnmpAuthProtocol = "SHA256"
    snmpv3_auth_password: SecretStr | None = None
    snmpv3_priv_protocol: SnmpPrivacyProtocol = "AES128"
    snmpv3_priv_password: SecretStr | None = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        return normalize_hostname(value)

    @field_validator("device_name")
    @classmethod
    def normalize_device_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("device name cannot be blank")
        return normalized

    @field_validator("snmpv3_username")
    @classmethod
    def validate_snmpv3_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not _SNMPV3_USER.fullmatch(normalized):
            raise ValueError("SNMPv3 username contains unsupported characters")
        return normalized

    @model_validator(mode="after")
    def validate_credentials(self) -> DeviceCreate:
        community = _secret_value(self.community)
        auth_password = _secret_value(self.snmpv3_auth_password)
        priv_password = _secret_value(self.snmpv3_priv_password)
        if self.snmp_version == "v2c":
            if not _valid_secret(community, minimum=1, maximum=255):
                raise ValueError("SNMP v2c requires a printable community string")
            if self.snmpv3_username or auth_password or priv_password:
                raise ValueError("SNMPv3 credentials cannot be supplied for an SNMP v2c device")
            return self

        if community:
            raise ValueError("SNMPv3 uses a user security model, not a community string")
        if not self.snmpv3_username:
            raise ValueError("SNMPv3 username is required")
        if self.snmpv3_security_level in {"authNoPriv", "authPriv"} and not _valid_secret(
            auth_password, minimum=8, maximum=255
        ):
            raise ValueError("authenticated SNMPv3 requires an 8-255 character auth password")
        if self.snmpv3_security_level == "authPriv" and not _valid_secret(
            priv_password, minimum=8, maximum=255
        ):
            raise ValueError("private SNMPv3 requires an 8-255 character privacy password")
        if self.snmpv3_security_level == "noAuthNoPriv" and (auth_password or priv_password):
            raise ValueError("noAuthNoPriv cannot include auth or privacy passwords")
        if self.snmpv3_security_level == "authNoPriv" and priv_password:
            raise ValueError("authNoPriv cannot include a privacy password")
        return self

    def security_level(self) -> SnmpSecurityLevel:
        return "community" if self.snmp_version == "v2c" else self.snmpv3_security_level

    def credential_payload(self) -> dict[str, str]:
        if self.snmp_version == "v2c":
            return {"community": _secret_value(self.community) or ""}
        payload = {
            "username": self.snmpv3_username or "",
            "security_level": self.snmpv3_security_level,
            "auth_protocol": self.snmpv3_auth_protocol,
            "priv_protocol": self.snmpv3_priv_protocol,
        }
        auth_password = _secret_value(self.snmpv3_auth_password)
        priv_password = _secret_value(self.snmpv3_priv_password)
        if auth_password:
            payload["auth_password"] = auth_password
        if priv_password:
            payload["priv_password"] = priv_password
        return payload


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None

    @field_validator("device_name")
    @classmethod
    def normalize_device_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("device name cannot be blank")
        return normalized

    @model_validator(mode="after")
    def require_change(self) -> DeviceUpdate:
        if self.device_name is None and self.enabled is None:
            raise ValueError("at least one device field must be supplied")
        return self


class DeviceRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    hostname: str
    device_name: str
    snmp_version: SnmpVersion
    snmp_port: int
    snmp_security_level: SnmpSecurityLevel
    credentials_configured: bool
    enabled: bool
    status: DeviceStatus
    ping_latency_ms: float | None
    snmp_status: DeviceStatus
    sys_name: str | None
    sys_description: str | None
    sys_object_id: str | None
    uptime_seconds: int | None
    interface_total: int | None
    interface_up: int | None
    interface_down: int | None
    interface_unknown: int | None
    last_polled_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class DeviceList(BaseModel):
    devices: list[DeviceRead]
    total: int
    up: int
    down: int
    unknown: int


@dataclass(frozen=True)
class DevicePollTarget:
    id: str
    hostname: str
    snmp_port: int
    snmp_version: SnmpVersion
    credentials: dict[str, str]


@dataclass(frozen=True)
class DevicePollResult:
    status: DeviceStatus
    ping_latency_ms: float | None
    snmp_status: DeviceStatus
    sys_name: str | None = None
    sys_description: str | None = None
    sys_object_id: str | None = None
    uptime_seconds: int | None = None
    interface_total: int | None = None
    interface_up: int | None = None
    interface_down: int | None = None
    interface_unknown: int | None = None
    error: str | None = None


class CredentialCipher:
    def __init__(self, key: SecretStr) -> None:
        try:
            self._fernet = Fernet(key.get_secret_value().encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise ValueError("OPSPILOT_SNMP_CREDENTIAL_KEY must be a valid Fernet key") from error

    def encrypt(self, payload: dict[str, str]) -> bytes:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._fernet.encrypt(serialized)

    def decrypt(self, token: bytes) -> dict[str, str]:
        try:
            decoded = json.loads(self._fernet.decrypt(token))
        except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise CredentialDecryptionError("SNMP credentials could not be decrypted") from error
        if not isinstance(decoded, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in decoded.items()
        ):
            raise CredentialDecryptionError("SNMP credential payload is invalid")
        return decoded


class NetworkDeviceStore:
    """CRUD and poll-result persistence inside the existing IncidentLedger DB."""

    PUBLIC_COLUMNS = """
        id, hostname, device_name, snmp_version, snmp_port, snmp_security_level,
        enabled, status, ping_latency_ms, snmp_status, sys_name, sys_description,
        sys_object_id, uptime_seconds, interface_total, interface_up, interface_down,
        interface_unknown, last_polled_at, last_success_at, last_error, created_at, updated_at
    """

    def __init__(self, ledger: IncidentLedger, cipher: CredentialCipher | None) -> None:
        self.ledger = ledger
        self.cipher = cipher

    @staticmethod
    def _to_public(row: sqlite3.Row) -> DeviceRead:
        payload = dict(row)
        payload["enabled"] = bool(payload["enabled"])
        payload["credentials_configured"] = True
        return DeviceRead.model_validate(payload)

    def list_devices(self) -> DeviceList:
        with self.ledger.transaction(immediate=False) as connection:
            rows = connection.execute(
                f"SELECT {self.PUBLIC_COLUMNS} "  # noqa: S608 - columns are a class constant
                "FROM network_devices ORDER BY device_name, hostname"
            ).fetchall()
        devices = [self._to_public(row) for row in rows]
        return DeviceList(
            devices=devices,
            total=len(devices),
            up=sum(device.status == "UP" for device in devices),
            down=sum(device.status == "DOWN" for device in devices),
            unknown=sum(device.status == "UNKNOWN" for device in devices),
        )

    def get_device(self, device_id: str) -> DeviceRead | None:
        with self.ledger.transaction(immediate=False) as connection:
            row = connection.execute(
                f"SELECT {self.PUBLIC_COLUMNS} "  # noqa: S608 - columns are a class constant
                "FROM network_devices WHERE id=?",
                (device_id,),
            ).fetchone()
        return self._to_public(row) if row else None

    def create_device(self, request: DeviceCreate) -> DeviceRead:
        if self.cipher is None:
            raise CredentialsUnavailableError(
                "SNMP credential encryption is not configured on this server"
            )
        now = _iso()
        device_id = str(uuid.uuid4())
        ciphertext = self.cipher.encrypt(request.credential_payload())
        try:
            with self.ledger.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO network_devices(
                        id, hostname, device_name, snmp_version, snmp_port,
                        snmp_security_level, credentials_encrypted, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        request.hostname,
                        request.device_name,
                        request.snmp_version,
                        request.snmp_port,
                        request.security_level(),
                        ciphertext,
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as error:
            if "network_devices.hostname" in str(error):
                raise DuplicateDeviceError("a device with this hostname already exists") from error
            raise
        created = self.get_device(device_id)
        if created is None:
            raise RuntimeError("device disappeared immediately after creation")
        return created

    def update_device(self, device_id: str, request: DeviceUpdate) -> DeviceRead:
        assignments: list[str] = []
        values: list[Any] = []
        if request.device_name is not None:
            assignments.append("device_name=?")
            values.append(request.device_name)
        if request.enabled is not None:
            assignments.append("enabled=?")
            values.append(int(request.enabled))
            if not request.enabled:
                assignments.extend(
                    [
                        "status='UNKNOWN'",
                        "snmp_status='UNKNOWN'",
                        "ping_latency_ms=NULL",
                        "last_error=NULL",
                    ]
                )
        assignments.append("updated_at=?")
        values.extend([_iso(), device_id])
        with self.ledger.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE network_devices SET {', '.join(assignments)} WHERE id=?",  # noqa: S608
                values,
            )
        if cursor.rowcount != 1:
            raise DeviceNotFoundError("network device not found")
        updated = self.get_device(device_id)
        if updated is None:
            raise DeviceNotFoundError("network device not found")
        return updated

    def delete_device(self, device_id: str) -> bool:
        with self.ledger.transaction() as connection:
            cursor = connection.execute("DELETE FROM network_devices WHERE id=?", (device_id,))
        return cursor.rowcount == 1

    def list_poll_targets(self) -> list[DevicePollTarget]:
        if self.cipher is None:
            raise CredentialsUnavailableError(
                "SNMP credential encryption is not configured on this server"
            )
        with self.ledger.transaction(immediate=False) as connection:
            rows = connection.execute(
                """
                SELECT id, hostname, snmp_port, snmp_version, credentials_encrypted
                  FROM network_devices
                 WHERE enabled=1
                 ORDER BY hostname
                """
            ).fetchall()
        targets: list[DevicePollTarget] = []
        for row in rows:
            token = row["credentials_encrypted"]
            if not isinstance(token, bytes):
                raise CredentialDecryptionError("SNMP credential ciphertext has an invalid type")
            targets.append(
                DevicePollTarget(
                    id=str(row["id"]),
                    hostname=str(row["hostname"]),
                    snmp_port=int(row["snmp_port"]),
                    snmp_version=str(row["snmp_version"]),  # type: ignore[arg-type]
                    credentials=self.cipher.decrypt(token),
                )
            )
        return targets

    def record_poll(self, device_id: str, result: DevicePollResult) -> None:
        now = _iso()
        error = result.error[:1000] if result.error else None
        success = result.status == "UP" or result.snmp_status == "UP"
        with self.ledger.transaction() as connection:
            connection.execute(
                """
                UPDATE network_devices
                   SET status=?, ping_latency_ms=?, snmp_status=?, sys_name=?,
                       sys_description=?, sys_object_id=?, uptime_seconds=?,
                       interface_total=?, interface_up=?, interface_down=?,
                       interface_unknown=?, last_polled_at=?,
                       last_success_at=CASE WHEN ? THEN ? ELSE last_success_at END,
                       last_error=?, updated_at=?
                 WHERE id=?
                """,
                (
                    result.status,
                    result.ping_latency_ms,
                    result.snmp_status,
                    result.sys_name,
                    result.sys_description,
                    result.sys_object_id,
                    result.uptime_seconds,
                    result.interface_total,
                    result.interface_up,
                    result.interface_down,
                    result.interface_unknown,
                    now,
                    int(success),
                    now,
                    error,
                    now,
                    device_id,
                ),
            )
