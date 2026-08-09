from __future__ import annotations

from opspilot_enterprise.models import ProcessRecord
from opspilot_enterprise.synthetic import detect_synthetic_load
from opspilot_enterprise.telemetry import CommandSpec, execute_read_only


def process(command_argv: list[str], *, pid: int = 123, cpu: float = 398.0) -> ProcessRecord:
    return ProcessRecord(
        pid=pid,
        ppid=100,
        uid=1000,
        user="tester",
        state="R",
        comm=command_argv[0].split("/")[-1],
        executable=command_argv[0],
        cwd="/home/tester",
        command_line=" ".join(command_argv),
        command_argv=command_argv,
        cpu_percent=cpu,
        memory_percent=1.5,
        elapsed_seconds=12,
        parent_chain=[100, 1],
    )


def test_stress_ng_is_confirmed_with_exact_command() -> None:
    command = ["/usr/bin/stress-ng", "--cpu", "4", "--timeout", "120s", "--metrics-brief"]
    findings = detect_synthetic_load([process(command)])
    assert len(findings) == 1
    assert findings[0].classification == "confirmed"
    assert findings[0].confidence == "high"
    assert findings[0].tool == "stress-ng"
    assert findings[0].exact_command == " ".join(command)


def test_busy_python_loop_is_suspected_manual_load() -> None:
    command = [
        "/usr/bin/python3",
        "-c",
        "import hashlib; while True: hashlib.sha256(b'x').digest()",
    ]
    findings = detect_synthetic_load([process(command)])
    assert any(item.tool == "manual-load-script" for item in findings)


def test_normal_business_process_is_not_called_synthetic() -> None:
    findings = detect_synthetic_load(
        [process(["/usr/bin/java", "-jar", "/opt/payments/service.jar"], cpu=325)]
    )
    assert findings == []


def test_allowlisted_command_execution_has_hash_and_no_shell() -> None:
    result = execute_read_only(CommandSpec("uptime_test", ("uptime",), timeout_seconds=5))
    assert result.return_code == 0
    assert result.argv[0].startswith("/")
    assert len(result.sha256) == 64


def test_non_allowlisted_binary_is_rejected() -> None:
    try:
        execute_read_only(CommandSpec("bad", ("curl", "https://example.com")))
    except ValueError as error:
        assert "not allowlisted" in str(error)
    else:
        raise AssertionError("non-allowlisted command unexpectedly executed")
