"""Deterministic detection of synthetic and manually injected resource load.

The LLM receives these findings, but does not decide whether a known load tool is
present. That decision is made here from exact `/proc/<pid>/cmdline` evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath

from .models import ProcessRecord, SyntheticFinding


@dataclass(frozen=True)
class Signature:
    name: str
    executable: re.Pattern[str]
    arguments: re.Pattern[str] | None
    confidence: str
    rationale: str


SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "stress-ng",
        re.compile(r"(?i)(?:^|/)(stress-ng)$"),
        None,
        "high",
        "stress-ng is an explicit synthetic workload generator",
    ),
    Signature(
        "stress",
        re.compile(r"(?i)(?:^|/)(stress)$"),
        re.compile(r"(?i)(?:--cpu|--vm|--io|--hdd|-c|-m|-i|-d)"),
        "high",
        "stress with worker flags is an explicit synthetic workload generator",
    ),
    Signature(
        "sysbench",
        re.compile(r"(?i)(?:^|/)(sysbench)$"),
        re.compile(r"(?i)\b(?:cpu|memory|fileio|threads)\b.*\brun\b"),
        "high",
        "sysbench run mode is a deliberate benchmark",
    ),
    Signature(
        "lookbusy",
        re.compile(r"(?i)(?:^|/)(lookbusy)$"),
        None,
        "high",
        "lookbusy intentionally simulates CPU, memory, or disk load",
    ),
    Signature(
        "cpuburn",
        re.compile(r"(?i)(?:^|/)(?:burn[A-Za-z0-9_-]*|cpuburn)$"),
        None,
        "high",
        "CPU burn binaries intentionally saturate processors",
    ),
    Signature(
        "fio",
        re.compile(r"(?i)(?:^|/)(fio)$"),
        re.compile(r"(?i)(?:--name|--rw|--filename|\.fio\b)"),
        "high",
        "fio with a job specification is an intentional I/O workload",
    ),
    Signature(
        "iperf",
        re.compile(r"(?i)(?:^|/)(?:iperf|iperf3)$"),
        re.compile(r"(?i)(?:\s-[cs]\b|--client|--server)"),
        "high",
        "iperf is an intentional network throughput test",
    ),
    Signature(
        "yes-loop",
        re.compile(r"(?i)(?:^|/)(yes)$"),
        None,
        "medium",
        "yes commonly creates intentional CPU load but can have benign uses",
    ),
    Signature(
        "openssl-speed",
        re.compile(r"(?i)(?:^|/)(openssl)$"),
        re.compile(r"(?i)\bspeed\b"),
        "high",
        "openssl speed is an explicit CPU benchmark",
    ),
)

SCRIPT_NAME_RE = re.compile(
    r"(?i)(?:^|[/_.-])(?:stress|load|burn|benchmark|perf[-_]?test|cpu[-_]?test|"
    r"memory[-_]?test|oom[-_]?test)(?:[/_.-]|$)"
)
BUSY_LOOP_RE = re.compile(
    r"(?is)(?:while\s+(?:true|:|1).*?(?:do|:)|for\s*\(\s*;\s*;\s*\)|"
    r"while\s*\(\s*1\s*\)).{0,300}"
)
LOAD_PRIMITIVE_RE = re.compile(
    r"(?i)(?:hashlib|sha256|math\.sqrt|multiprocessing|threading|/dev/zero|"
    r"dd\s+if=|allocate|bytearray|fork\s*\()"
)


def _display_executable(process: ProcessRecord) -> str:
    if process.executable:
        return process.executable.removesuffix(" (deleted)")
    if process.command_argv:
        return process.command_argv[0]
    return process.comm


def detect_synthetic_load(processes: list[ProcessRecord]) -> list[SyntheticFinding]:
    """Return strongest evidence first, de-duplicated by PID and signature."""

    findings: list[SyntheticFinding] = []
    seen: set[tuple[int, str]] = set()

    for process in processes:
        executable = _display_executable(process)
        command = process.command_line
        basename = PurePath(executable).name
        target = f"/{basename}"
        matched_known_tool = False

        for signature in SIGNATURES:
            if not signature.executable.search(target):
                continue
            if signature.arguments and not signature.arguments.search(command):
                continue
            key = (process.pid, signature.name)
            if key in seen:
                continue
            seen.add(key)
            matched_known_tool = True
            findings.append(
                SyntheticFinding(
                    pid=process.pid,
                    classification=("confirmed" if signature.confidence == "high" else "suspected"),
                    confidence=signature.confidence,  # type: ignore[arg-type]
                    tool=signature.name,
                    exact_command=command,
                    signature=f"known-tool:{signature.name}",
                    rationale=signature.rationale,
                    parent_chain=process.parent_chain,
                )
            )

        argv_tail = " ".join(process.command_argv[1:])
        interpreter = basename.lower() in {
            "bash",
            "sh",
            "dash",
            "zsh",
            "python",
            "python3",
            "perl",
            "ruby",
            "node",
        }
        named_test = SCRIPT_NAME_RE.search(command)
        busy_script = (
            interpreter and BUSY_LOOP_RE.search(argv_tail) and LOAD_PRIMITIVE_RE.search(argv_tail)
        )
        if not matched_known_tool and (named_test or busy_script):
            key = (process.pid, "manual-load-script")
            if key not in seen:
                seen.add(key)
                findings.append(
                    SyntheticFinding(
                        pid=process.pid,
                        classification="suspected",
                        confidence="medium",
                        tool="manual-load-script",
                        exact_command=command,
                        signature=(
                            "script-name-and-command" if named_test else "interpreter-busy-loop"
                        ),
                        rationale=(
                            "The command or script name identifies a load/benchmark test"
                            if named_test
                            else "An interpreter command contains a busy loop and load primitive"
                        ),
                        parent_chain=process.parent_chain,
                    )
                )

    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (rank[item.confidence], -item.pid, item.tool))
