"""Bounded, read-only Linux forensic telemetry with exact process arguments."""

from __future__ import annotations

import os
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from .models import CommandEvidence, HostTelemetry, ProcessRecord
from .security import evidence_hash, redact_argv, redact_text, sha256_bytes
from .synthetic import detect_synthetic_load

SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ALLOWED_BINARIES = {
    "cat",
    "df",
    "dmesg",
    "free",
    "ip",
    "journalctl",
    "lsblk",
    "lscpu",
    "mpstat",
    "nstat",
    "ps",
    "ss",
    "systemctl",
    "top",
    "uptime",
    "vmstat",
}


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: float = 15
    optional: bool = False


@dataclass(frozen=True)
class ProcStat:
    pid: int
    ppid: int
    state: str
    ticks: int
    start_ticks: int
    rss_pages: int


def _binary(name: str) -> str | None:
    if name not in ALLOWED_BINARIES:
        raise ValueError(f"binary is not allowlisted: {name}")
    path = shutil.which(name, path=SAFE_PATH)
    if not path:
        return None
    resolved = str(Path(path).resolve())
    if not any(
        resolved.startswith(prefix + "/") for prefix in ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
    ):
        raise ValueError(f"binary resolved outside trusted directories: {resolved}")
    return resolved


def _read_limited(handle: BinaryIO, limit: int) -> tuple[bytes, bool]:
    handle.seek(0)
    data = handle.read(limit + 1)
    return data[:limit], len(data) > limit


def execute_read_only(
    spec: CommandSpec,
    *,
    max_bytes: int = 512_000,
    default_timeout: float = 15,
) -> CommandEvidence:
    """Execute one internal fixed command without a shell and with group timeout."""

    started_at = datetime.now(UTC)
    started = time.monotonic()
    binary = _binary(spec.argv[0])
    if binary is None:
        body = f"optional binary unavailable: {spec.argv[0]}"
        return CommandEvidence(
            name=spec.name,
            argv=list(spec.argv),
            started_at=started_at,
            duration_ms=0,
            return_code=127,
            stdout="",
            stderr=body,
            sha256=sha256_bytes(body.encode()),
        )

    argv = (binary, *spec.argv[1:])
    timeout = min(spec.timeout_seconds, default_timeout)
    timed_out = False
    return_code = 126
    raw_stdout = b""
    raw_stderr = b""
    truncated = False

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed allowlisted argument vector
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env={"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"},
                close_fds=True,
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    return_code = process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    return_code = process.wait(timeout=2)
            raw_stdout, stdout_cut = _read_limited(stdout_file, max_bytes)
            raw_stderr, stderr_cut = _read_limited(stderr_file, min(max_bytes // 4, 128_000))
            truncated = stdout_cut or stderr_cut
        except OSError as error:
            return_code = 126
            raw_stderr = f"{type(error).__name__}: {error}".encode()

    stdout, stdout_redaction_cut = redact_text(
        raw_stdout.decode("utf-8", errors="replace"), max_chars=max_bytes
    )
    stderr, stderr_redaction_cut = redact_text(
        raw_stderr.decode("utf-8", errors="replace"), max_chars=min(max_bytes // 4, 128_000)
    )
    truncated = truncated or stdout_redaction_cut or stderr_redaction_cut
    digest_input = b"\x00".join(
        ["\n".join(argv).encode(), str(return_code).encode(), stdout.encode(), stderr.encode()]
    )
    return CommandEvidence(
        name=spec.name,
        argv=list(argv),
        started_at=started_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=truncated,
        sha256=sha256_bytes(digest_input),
    )


def default_command_specs(since_minutes: int) -> tuple[CommandSpec, ...]:
    since = f"{max(1, min(since_minutes, 1440))} minutes ago"
    return (
        CommandSpec(
            "process_tree",
            (
                "ps",
                "-eo",
                "pid=,ppid=,uid=,user=,stat=,lstart=,etimes=,pcpu=,pmem=,comm=,args=",
                "--forest",
                "--sort=-pcpu",
            ),
        ),
        CommandSpec("top_snapshot", ("top", "-b", "-n", "1", "-w", "512")),
        CommandSpec(
            "kernel_journal",
            (
                "journalctl",
                "-k",
                "--since",
                since,
                "-n",
                "2000",
                "--no-pager",
                "-o",
                "short-iso-precise",
            ),
        ),
        CommandSpec("kernel_ring", ("dmesg", "--ctime", "--color=never"), optional=True),
        CommandSpec(
            "system_journal",
            ("journalctl", "--since", since, "-n", "2000", "--no-pager", "-o", "short-iso-precise"),
        ),
        CommandSpec("failed_units", ("systemctl", "--failed", "--no-pager", "--plain")),
        CommandSpec("uptime", ("uptime",)),
        CommandSpec("cpu", ("lscpu",)),
        CommandSpec(
            "cpu_sample", ("mpstat", "-P", "ALL", "1", "3"), timeout_seconds=8, optional=True
        ),
        CommandSpec("vmstat", ("vmstat", "-w", "1", "5"), timeout_seconds=10),
        CommandSpec("memory", ("free", "-w", "-b")),
        CommandSpec("filesystems", ("df", "-P", "-T", "-h")),
        CommandSpec("inodes", ("df", "-P", "-i")),
        CommandSpec("block_devices", ("lsblk", "-J", "-O", "-b")),
        CommandSpec("socket_summary", ("ss", "-s")),
        CommandSpec("socket_tcp", ("ss", "-H", "-t", "-a", "-n", "-p", "-o")),
        CommandSpec("socket_udp", ("ss", "-H", "-u", "-a", "-n", "-p")),
        CommandSpec("link_stats", ("ip", "-s", "-j", "link", "show")),
        CommandSpec("addresses", ("ip", "-j", "address", "show")),
        CommandSpec("routes", ("ip", "-j", "route", "show", "table", "all")),
        CommandSpec("network_counters", ("nstat", "-a", "-z"), optional=True),
    )


def _read_proc_stat(pid: int) -> ProcStat | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        close = raw.rfind(")")
        if close < 0:
            return None
        fields = raw[close + 2 :].split()
        return ProcStat(
            pid=pid,
            state=fields[0],
            ppid=int(fields[1]),
            ticks=int(fields[11]) + int(fields[12]),
            start_ticks=int(fields[19]),
            rss_pages=max(0, int(fields[21])),
        )
    except (OSError, ValueError, IndexError):
        return None


def _system_ticks() -> int:
    try:
        line = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0]
        return sum(int(value) for value in line.split()[1:])
    except (OSError, ValueError, IndexError):
        return 0


def _proc_snapshot(max_processes: int) -> dict[int, ProcStat]:
    result: dict[int, ProcStat] = {}
    try:
        pids = sorted(int(item.name) for item in Path("/proc").iterdir() if item.name.isdigit())
    except OSError:
        return result
    for pid in pids[:max_processes]:
        record = _read_proc_stat(pid)
        if record:
            result[pid] = record
    return result


def _read_text(path: Path, limit: int = 8192) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _read_link(path: Path) -> str | None:
    try:
        value = os.readlink(path)
        return redact_text(value, max_chars=4096)[0]
    except OSError:
        return None


def _username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _uid(pid: int) -> int:
    status = _read_text(Path(f"/proc/{pid}/status"), 16_384)
    for line in status.splitlines():
        if line.startswith("Uid:"):
            try:
                return int(line.split()[1])
            except (ValueError, IndexError):
                break
    return 0


def _command(pid: int, comm: str) -> tuple[list[str], str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()[:65_536]
    except OSError:
        raw = b""
    argv = [item.decode("utf-8", errors="replace") for item in raw.split(b"\x00") if item]
    if not argv:
        argv = [f"[{comm}]"]
    safe_argv = redact_argv(argv[:256])
    command_line = " ".join(_shell_display(item) for item in safe_argv)
    return safe_argv, command_line[:65_536]


def _shell_display(value: str) -> str:
    """Display an argv element unambiguously without producing executable shell text."""

    if value and all(ch.isalnum() or ch in "@%_+=:,./-" for ch in value):
        return value
    return repr(value)


def _parent_chain(pid: int, stats: dict[int, ProcStat], limit: int = 32) -> list[int]:
    chain: list[int] = []
    seen = {pid}
    cursor = pid
    for _ in range(limit):
        record = stats.get(cursor)
        if not record or record.ppid <= 0 or record.ppid in seen:
            break
        chain.append(record.ppid)
        seen.add(record.ppid)
        cursor = record.ppid
    return chain


def collect_processes(*, sample_seconds: float, max_processes: int) -> list[ProcessRecord]:
    first_total = _system_ticks()
    first = _proc_snapshot(max_processes)
    time.sleep(sample_seconds)
    second_total = _system_ticks()
    second = _proc_snapshot(max_processes)
    total_delta = max(1, second_total - first_total)
    cpu_count = max(1, os.cpu_count() or 1)
    clock_ticks = max(1, os.sysconf("SC_CLK_TCK"))
    page_size = max(1, os.sysconf("SC_PAGE_SIZE"))
    try:
        total_memory = (
            int(Path("/proc/meminfo").read_text().split("MemTotal:", 1)[1].split()[0]) * 1024
        )
    except (OSError, ValueError, IndexError):
        total_memory = 1
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        uptime = 0

    records: list[ProcessRecord] = []
    for pid, stat in second.items():
        proc_root = Path(f"/proc/{pid}")
        comm = _read_text(proc_root / "comm", 4096).strip() or "unknown"
        argv, command_line = _command(pid, comm)
        uid = _uid(pid)
        previous = first.get(pid)
        process_delta = max(0, stat.ticks - previous.ticks) if previous else 0
        cpu_percent = (process_delta / total_delta) * 100 * cpu_count
        memory_percent = ((stat.rss_pages * page_size) / max(total_memory, 1)) * 100
        executable = _read_link(proc_root / "exe")
        cwd = _read_link(proc_root / "cwd")
        cgroup = [
            redact_text(line, max_chars=2048)[0]
            for line in _read_text(proc_root / "cgroup", 32_768).splitlines()[:32]
        ]
        elapsed = max(0, int(uptime - (stat.start_ticks / clock_ticks)))
        records.append(
            ProcessRecord(
                pid=pid,
                ppid=stat.ppid,
                uid=uid,
                user=_username(uid),
                state=stat.state,
                comm=comm[:256],
                executable=executable,
                cwd=cwd,
                command_line=command_line,
                command_argv=argv,
                cpu_percent=round(max(0, cpu_percent), 2),
                memory_percent=round(max(0, memory_percent), 3),
                elapsed_seconds=elapsed,
                cgroup=cgroup,
                parent_chain=_parent_chain(pid, second),
                executable_deleted=bool(executable and executable.endswith(" (deleted)")),
            )
        )
    return sorted(records, key=lambda item: (-item.cpu_percent, -item.memory_percent, item.pid))


class ForensicTelemetryCollector:
    def __init__(
        self,
        *,
        command_timeout_seconds: float = 15,
        total_budget_seconds: float = 45,
        max_command_bytes: int = 512_000,
        max_processes: int = 4096,
        cpu_sample_seconds: float = 0.5,
    ) -> None:
        self.command_timeout_seconds = command_timeout_seconds
        self.total_budget_seconds = total_budget_seconds
        self.max_command_bytes = max_command_bytes
        self.max_processes = max_processes
        self.cpu_sample_seconds = cpu_sample_seconds

    def collect(self, *, since_minutes: int = 10) -> HostTelemetry:
        started = time.monotonic()
        errors: list[str] = []
        commands: dict[str, CommandEvidence] = {}
        processes: list[ProcessRecord] = []

        try:
            processes = collect_processes(
                sample_seconds=self.cpu_sample_seconds,
                max_processes=self.max_processes,
            )
        except Exception as error:  # collector must return partial evidence
            errors.append(f"process_collection:{type(error).__name__}:{error}")

        for spec in default_command_specs(since_minutes):
            if time.monotonic() - started >= self.total_budget_seconds:
                errors.append(f"budget_exhausted_before:{spec.name}")
                break
            result = execute_read_only(
                spec,
                max_bytes=self.max_command_bytes,
                default_timeout=self.command_timeout_seconds,
            )
            commands[spec.name] = result
            if result.return_code != 0 and not spec.optional:
                errors.append(f"command_failed:{spec.name}:rc={result.return_code}")

        findings = detect_synthetic_load(processes)
        payload = {
            "node": socket.gethostname(),
            "commands": {name: item.model_dump(mode="json") for name, item in commands.items()},
            "processes": [item.model_dump(mode="json") for item in processes],
            "synthetic_findings": [item.model_dump(mode="json") for item in findings],
            "collector_errors": errors,
        }
        return HostTelemetry(
            node=socket.gethostname(),
            collector_errors=errors,
            commands=commands,
            processes=processes,
            synthetic_findings=findings,
            evidence_sha256=evidence_hash(payload),
        )
