"""Async ICMP/SNMP polling for devices stored in the OpsPilot SQLite ledger."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import re
import time
from dataclasses import dataclass
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-untyped]
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_AUTH_NONE,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    USM_PRIV_NONE,
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
)

from .devices import DevicePollResult, DevicePollTarget, NetworkDeviceStore

logger = logging.getLogger(__name__)

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_NUMBER = "1.3.6.1.2.1.2.1.0"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

AUTH_PROTOCOLS: dict[str, Any] = {
    "SHA": USM_AUTH_HMAC96_SHA,
    "SHA224": USM_AUTH_HMAC128_SHA224,
    "SHA256": USM_AUTH_HMAC192_SHA256,
    "SHA384": USM_AUTH_HMAC256_SHA384,
    "SHA512": USM_AUTH_HMAC384_SHA512,
}
PRIVACY_PROTOCOLS: dict[str, Any] = {
    "AES128": USM_PRIV_CFB128_AES,
    "AES192": USM_PRIV_CFB192_AES,
    "AES256": USM_PRIV_CFB256_AES,
}
PING_TIME = re.compile(rb"\btime[=<]([0-9]+(?:\.[0-9]+)?)\s*ms\b", re.IGNORECASE)


class SnmpPollError(RuntimeError):
    pass


@dataclass(frozen=True)
class SnmpMetrics:
    sys_name: str
    sys_description: str
    sys_object_id: str
    uptime_seconds: int
    interface_total: int
    interface_up: int
    interface_down: int
    interface_unknown: int


def _safe_error(value: object, *, maximum: int = 500) -> str:
    message = " ".join(str(value).replace("\x00", "").split())
    return (message or type(value).__name__)[:maximum]


def _auth_data(target: DevicePollTarget) -> CommunityData | UsmUserData:
    credentials = target.credentials
    if target.snmp_version == "v2c":
        community = credentials.get("community")
        if not community:
            raise SnmpPollError("stored SNMP v2c credentials are incomplete")
        return CommunityData(community, mpModel=1)  # noqa: S508 - v2c is an explicit feature

    username = credentials.get("username")
    security_level = credentials.get("security_level")
    if not username or security_level not in {"noAuthNoPriv", "authNoPriv", "authPriv"}:
        raise SnmpPollError("stored SNMPv3 credentials are incomplete")
    if security_level == "noAuthNoPriv":
        return UsmUserData(
            username,
            authProtocol=USM_AUTH_NONE,
            privProtocol=USM_PRIV_NONE,
        )

    auth_password = credentials.get("auth_password")
    auth_protocol = AUTH_PROTOCOLS.get(credentials.get("auth_protocol", ""))
    if not auth_password or auth_protocol is None:
        raise SnmpPollError("stored SNMPv3 authentication credentials are incomplete")
    if security_level == "authNoPriv":
        return UsmUserData(
            username,
            authKey=auth_password,
            authProtocol=auth_protocol,
            privProtocol=USM_PRIV_NONE,
        )

    priv_password = credentials.get("priv_password")
    priv_protocol = PRIVACY_PROTOCOLS.get(credentials.get("priv_protocol", ""))
    if not priv_password or priv_protocol is None:
        raise SnmpPollError("stored SNMPv3 privacy credentials are incomplete")
    return UsmUserData(
        username,
        authKey=auth_password,
        privKey=priv_password,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol,
    )


def _is_ipv6(hostname: str) -> bool:
    try:
        return ipaddress.ip_address(hostname).version == 6
    except ValueError:
        return False


async def poll_icmp(hostname: str, timeout_seconds: float) -> tuple[bool, float | None, str | None]:
    arguments = ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout_seconds)))]
    if _is_ipv6(hostname):
        arguments.append("-6")
    arguments.append(hostname)
    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return False, None, "ICMP ping executable is unavailable"
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds + 1.0
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        return False, None, "ICMP probe timed out"
    if process.returncode != 0:
        detail = _safe_error(stderr or stdout)
        return False, None, f"ICMP probe failed: {detail}"
    match = PING_TIME.search(stdout)
    return True, (float(match.group(1)) if match else None), None


async def poll_snmp(
    target: DevicePollTarget, *, timeout_seconds: float, retries: int
) -> SnmpMetrics:
    engine = SnmpEngine()
    transport_type = Udp6TransportTarget if _is_ipv6(target.hostname) else UdpTransportTarget
    try:
        transport = await transport_type.create(
            (target.hostname, target.snmp_port), timeout=timeout_seconds, retries=retries
        )
        auth = _auth_data(target)
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            auth,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(SYS_DESCR)),
            ObjectType(ObjectIdentity(SYS_OBJECT_ID)),
            ObjectType(ObjectIdentity(SYS_UPTIME)),
            ObjectType(ObjectIdentity(SYS_NAME)),
            ObjectType(ObjectIdentity(IF_NUMBER)),
            lookupMib=False,
        )
        if error_indication:
            raise SnmpPollError(f"SNMP request failed: {_safe_error(error_indication)}")
        if error_status:
            position = int(error_index or 0)
            raise SnmpPollError(
                f"SNMP agent error at field {position}: {_safe_error(error_status)}"
            )
        if len(var_binds) != 5:
            raise SnmpPollError("SNMP agent returned an incomplete system response")

        values = [var_bind[1] for var_bind in var_binds]
        interface_states: list[int] = []
        async for walk_error, walk_status, walk_index, walk_binds in bulk_walk_cmd(
            engine,
            auth,
            transport,
            ContextData(),
            0,
            25,
            ObjectType(ObjectIdentity(IF_OPER_STATUS)),
            lookupMib=False,
            lexicographicMode=False,
            maxRows=512,
        ):
            if walk_error:
                raise SnmpPollError(f"SNMP interface walk failed: {_safe_error(walk_error)}")
            if walk_status:
                position = int(walk_index or 0)
                raise SnmpPollError(
                    f"SNMP interface error at field {position}: {_safe_error(walk_status)}"
                )
            for var_bind in walk_binds:
                try:
                    interface_states.append(int(var_bind[1]))
                except (TypeError, ValueError):
                    interface_states.append(0)

        reported_total = max(0, int(values[4]))
        walked_total = len(interface_states)
        total = max(reported_total, walked_total)
        up = interface_states.count(1)
        down = interface_states.count(2)
        unknown = max(0, total - up - down)
        return SnmpMetrics(
            sys_name=str(values[3].prettyPrint())[:255],
            sys_description=str(values[0].prettyPrint())[:2000],
            sys_object_id=str(values[1].prettyPrint())[:255],
            uptime_seconds=max(0, int(values[2]) // 100),
            interface_total=total,
            interface_up=up,
            interface_down=down,
            interface_unknown=unknown,
        )
    finally:
        engine.close_dispatcher()


async def poll_device(
    target: DevicePollTarget,
    *,
    icmp_timeout_seconds: float,
    snmp_timeout_seconds: float,
    snmp_retries: int,
) -> DevicePollResult:
    ping_task = asyncio.create_task(poll_icmp(target.hostname, icmp_timeout_seconds))
    snmp_task = asyncio.create_task(
        poll_snmp(target, timeout_seconds=snmp_timeout_seconds, retries=snmp_retries)
    )
    ping_outcome, snmp_outcome = await asyncio.gather(ping_task, snmp_task, return_exceptions=True)

    ping_ok: bool
    latency: float | None
    ping_error: str | None
    if isinstance(ping_outcome, BaseException):
        ping_ok, latency, ping_error = False, None, f"ICMP error: {_safe_error(ping_outcome)}"
    else:
        ping_ok, latency, ping_error = ping_outcome

    if isinstance(snmp_outcome, BaseException):
        metrics = None
        snmp_error = f"SNMP error: {_safe_error(snmp_outcome)}"
    else:
        metrics = snmp_outcome
        snmp_error = None

    errors = "; ".join(item for item in (ping_error, snmp_error) if item) or None
    return DevicePollResult(
        status="UP" if ping_ok else "DOWN",
        ping_latency_ms=latency,
        snmp_status="UP" if metrics else "DOWN",
        sys_name=metrics.sys_name if metrics else None,
        sys_description=metrics.sys_description if metrics else None,
        sys_object_id=metrics.sys_object_id if metrics else None,
        uptime_seconds=metrics.uptime_seconds if metrics else None,
        interface_total=metrics.interface_total if metrics else None,
        interface_up=metrics.interface_up if metrics else None,
        interface_down=metrics.interface_down if metrics else None,
        interface_unknown=metrics.interface_unknown if metrics else None,
        error=errors,
    )


class SnmpPollingWorker:
    def __init__(
        self,
        *,
        store: NetworkDeviceStore,
        poll_seconds: float = 30,
        icmp_timeout_seconds: float = 2,
        snmp_timeout_seconds: float = 2,
        snmp_retries: int = 1,
        max_concurrency: int = 20,
    ) -> None:
        self.store = store
        self.poll_seconds = poll_seconds
        self.icmp_timeout_seconds = icmp_timeout_seconds
        self.snmp_timeout_seconds = snmp_timeout_seconds
        self.snmp_retries = snmp_retries
        self.max_concurrency = max_concurrency

    async def run_once(self) -> int:
        targets = await asyncio.to_thread(self.store.list_poll_targets)
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def poll_and_record(target: DevicePollTarget) -> None:
            async with semaphore:
                result = await poll_device(
                    target,
                    icmp_timeout_seconds=self.icmp_timeout_seconds,
                    snmp_timeout_seconds=self.snmp_timeout_seconds,
                    snmp_retries=self.snmp_retries,
                )
                await asyncio.to_thread(self.store.record_poll, target.id, result)
                logger.info(
                    "network device polled",
                    extra={
                        "context": {
                            "device_id": target.id,
                            "hostname": target.hostname,
                            "status": result.status,
                            "snmp_status": result.snmp_status,
                        }
                    },
                )

        await asyncio.gather(*(poll_and_record(target) for target in targets))
        return len(targets)

    async def run_forever(self) -> None:
        logger.info(
            "SNMP polling worker started",
            extra={"context": {"poll_seconds": self.poll_seconds}},
        )
        while True:
            started = time.monotonic()
            try:
                await self.run_once()
            except Exception:
                logger.exception("SNMP polling cycle failed")
            elapsed = time.monotonic() - started
            await asyncio.sleep(max(0.5, self.poll_seconds - elapsed))
