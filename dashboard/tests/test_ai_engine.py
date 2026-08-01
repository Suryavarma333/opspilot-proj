import datetime as dt
from pathlib import Path
import subprocess
import sys
import unittest


FILES_DIR = Path(__file__).parents[1] / "files"
sys.path.insert(0, str(FILES_DIR))

from opspilot_ai_engine import (  # noqa: E402
    REMEDIATION_CATALOG,
    SENIOR_LINUX_RCA_SYSTEM_PROMPT,
    OpsPilotAIEngine,
    detect_anomalies,
    linear_regression_forecasts,
    route_question,
)


ALLOWED = {
    "uptime",
    "free -h",
    "df -hT",
    "df -ih",
    "du -xhd1 /var",
    "journalctl --disk-usage",
    "journalctl -p 3 -xb -n 50 --no-pager",
    "journalctl -p warning -n 80 --no-pager",
    "dmesg --level=err,warn",
    "ps -eo pid,user,pmem,rss,vsz,comm --sort=-rss",
    "cat /proc/pressure/memory",
    "systemctl --failed --no-pager",
    "systemctl list-units --type=service --state=failed --no-pager",
    "systemctl status nginx --no-pager",
    "systemctl status opspilot.service --no-pager",
    "ss -s",
    "ss -lntup",
    "ip -s link",
    "ip route show",
    "top -b -n 1",
    "who",
    "lastb -n 20",
    "sshd -T",
}


class DisabledClient:
    configured = False
    model = "none"


class UnsafeConfiguredClient:
    configured = True
    model = "test-model"

    def create_analysis(self, _payload):
        return {
            "status": "confirmed",
            "probable_root_cause": "Unsupported claim",
            "root_cause_diagnosis": "Unsupported diagnosis",
            "contributing_process": "PID 999 invented",
            "severity_level": "High",
            "confidence_percent": 99,
            "evidence": [{"source": "top", "excerpt": "this line is not in raw evidence"}],
            "resolution_theory": "Unsafe theory",
            "actionable_steps": [{"order": 1, "command": "rm -rf /", "purpose": "unsafe", "risk": "state_change", "requires_approval": False}],
            "recommended_action": {"action_id": "restart_nginx", "title": "invented", "command": "sudo anything", "reason": "test", "risk": "low", "executable": True},
        }


def fake_runner(command: str):
    outputs = {
        "top -b -n 1": "top - 12:00:00 up 1 day\nPID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND\n424 ops 20 0 100m 20m 1m R 88.0 2.0 1:00 worker",
        "journalctl -p 3 -xb -n 50 --no-pager": "Aug 01 12:00:01 node worker[424]: request queue saturated",
        "df -hT": "/dev/mapper/root ext4 96G 92G 4G 96% /",
        "ss -s": "TCP: 24 (estab 6, closed 8, orphaned 0, timewait 8)",
    }
    return {
        "status": "completed",
        "command": command,
        "stdout": outputs.get(command, "ok"),
        "stderr": "",
        "exit_code": 0,
        "generated_at": "2026-08-01T12:00:00Z",
        "truncated": False,
    }


def snapshot(**overrides):
    result = {
        "generated_at": "2026-08-01T12:00:00Z",
        "cpu": {"percent": 20.0, "count": 4, "load_1m": 0.4},
        "memory": {"percent": 40.0},
        "disk": {"percent": 30.0},
        "network": {},
        "services": [{"name": "nginx.service", "state": "active", "substate": "running"}],
        "processes": [{"pid": 424, "name": "worker", "cpu_percent": 88.0, "memory_percent": 2.0}],
    }
    result.update(overrides)
    return result


class OpsPilotAIEngineTests(unittest.TestCase):
    def test_prompt_forbids_guessing_and_requires_json(self):
        prompt = SENIOR_LINUX_RCA_SYSTEM_PROMPT.lower()
        self.assertIn("do not guess", prompt)
        self.assertIn("insufficient_evidence", prompt)
        self.assertIn("exactly one json object", prompt)
        self.assertIn("untrusted data", prompt)

    def test_router_returns_only_allowlisted_commands(self):
        commands = route_question("What is using my memory?", ALLOWED)
        self.assertIn("free -h", commands)
        self.assertIn("ps -eo pid,user,pmem,rss,vsz,comm --sort=-rss", commands)
        self.assertTrue(set(commands).issubset(ALLOWED))

    def test_anomaly_detection_covers_resources_and_service_state(self):
        data = snapshot(
            cpu={"percent": 92.0, "count": 4, "load_1m": 4.2},
            memory={"percent": 85.0},
            disk={"percent": 91.0},
            services=[{"name": "nginx.service", "state": "failed", "substate": "failed"}],
        )
        metrics = {item["metric"] for item in detect_anomalies(data)}
        self.assertEqual(metrics, {"CPU", "Memory", "Disk", "System Load", "Service State"})

    def test_regression_forecasts_exhaustion_within_twenty_four_hours(self):
        now = dt.datetime.now(dt.timezone.utc)
        samples = []
        for hour in range(11):
            samples.append(
                {
                    "timestamp": (now - dt.timedelta(hours=10 - hour)).isoformat(),
                    "disk": 80 + hour * 1.2,
                    "memory": 42.0,
                }
            )
        forecasts = linear_regression_forecasts(samples)
        self.assertEqual(len(forecasts), 1)
        self.assertEqual(forecasts[0]["metric"], "Storage")
        self.assertLessEqual(forecasts[0]["hours_to_exhaustion"], 24)
        self.assertGreaterEqual(forecasts[0]["confidence_percent"], 99)

    def test_flat_metrics_do_not_create_prediction(self):
        now = dt.datetime.now(dt.timezone.utc)
        samples = [
            {"timestamp": (now - dt.timedelta(minutes=index * 5)).isoformat(), "disk": 31.0, "memory": 43.0}
            for index in range(20)
        ]
        self.assertEqual(linear_regression_forecasts(samples), [])

    def test_fallback_states_more_data_needed_without_anomaly(self):
        engine = OpsPilotAIEngine(fake_runner, ALLOWED, client=DisabledClient())
        result = engine.answer_question("Why did CPU spike?", snapshot())
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertIn("no root cause is proven", result["probable_root_cause"].lower())
        self.assertEqual(result["analysis_mode"], "deterministic_fallback")
        self.assertTrue(set(result["commands_executed"]).issubset(ALLOWED))

    def test_server_drops_hallucinated_evidence_and_arbitrary_commands(self):
        engine = OpsPilotAIEngine(fake_runner, ALLOWED, client=UnsafeConfiguredClient())
        result = engine.answer_question("Why did CPU spike?", snapshot())
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["actionable_steps"][0]["command"], "")
        self.assertEqual(
            result["recommended_action"]["command"],
            REMEDIATION_CATALOG["none"]["command"],
        )
        self.assertFalse(result["recommended_action"]["executable"])

    def test_remediation_requires_one_time_exact_confirmation(self):
        calls = []

        def executor(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "cache cleaned", "")

        engine = OpsPilotAIEngine(
            fake_runner,
            ALLOWED,
            client=DisabledClient(),
            remediation_mode="enabled",
            remediation_executor=executor,
        )
        prepared = engine.prepare_remediation("clear_opspilot_cache")
        status, blocked = engine.execute_remediation(
            action_id="clear_opspilot_cache",
            approval_id=prepared["approval_id"],
            exact_command=prepared["exact_command"],
            confirmed=False,
        )
        self.assertEqual(status, 400)
        self.assertEqual(blocked["status"], "blocked")

        prepared = engine.prepare_remediation("clear_opspilot_cache")
        status, result = engine.execute_remediation(
            action_id="clear_opspilot_cache",
            approval_id=prepared["approval_id"],
            exact_command=prepared["exact_command"],
            confirmed=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(calls, [REMEDIATION_CATALOG["clear_opspilot_cache"]["argv"]])

        replay_status, replay = engine.execute_remediation(
            action_id="clear_opspilot_cache",
            approval_id=prepared["approval_id"],
            exact_command=prepared["exact_command"],
            confirmed=True,
        )
        self.assertEqual(replay_status, 409)
        self.assertEqual(replay["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
