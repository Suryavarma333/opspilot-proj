import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "files" / "opspilot_cpu_alert.py"
SPEC = importlib.util.spec_from_file_location("opspilot_cpu_alert", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class CpuAlertTests(unittest.TestCase):
    def test_cpu_calculation(self):
        self.assertEqual(MODULE.calculate_cpu_percent((100, 20), (200, 30)), 90.0)

    def test_four_high_samples_dispatch_once(self):
        state = MODULE.initial_state()
        events = []
        keys = []
        for _ in range(5):
            events.append(
                MODULE.advance_state(
                    state,
                    95.0,
                    high_samples=4,
                    recovery_samples=3,
                )
            )
            keys.append(state["idempotency_key"])
        self.assertEqual(events[:3], ["none", "none", "none"])
        self.assertEqual(events[3:], ["dispatch", "dispatch"])
        self.assertTrue(state["idempotency_key"].startswith("cpu-alert-"))
        self.assertEqual(keys[3], keys[4])

    def test_open_incident_does_not_redispatch(self):
        state = MODULE.initial_state()
        state["incident_open"] = True
        state["high_streak"] = 4
        event = MODULE.advance_state(state, 99.0, high_samples=4, recovery_samples=3)
        self.assertEqual(event, "none")

    def test_recovery_requires_three_low_samples(self):
        state = MODULE.initial_state()
        state["incident_open"] = True
        state["jira_key"] = "CORE-123"
        events = [
            MODULE.advance_state(
                state,
                70.0,
                high_samples=4,
                recovery_samples=3,
            )
            for _ in range(3)
        ]
        self.assertEqual(events, ["none", "none", "recovered"])
        self.assertFalse(state["incident_open"])
        self.assertEqual(state["jira_key"], "")

    def test_deadband_resets_streaks(self):
        state = MODULE.initial_state()
        MODULE.advance_state(state, 95.0, high_samples=4, recovery_samples=3)
        MODULE.advance_state(state, 85.0, high_samples=4, recovery_samples=3)
        self.assertEqual(state["high_streak"], 0)
        self.assertEqual(state["low_streak"], 0)

    def test_state_round_trip(self):
        state = MODULE.initial_state()
        state["jira_key"] = "CORE-456"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            MODULE.save_state(state, path)
            self.assertEqual(MODULE.load_state(path)["jira_key"], "CORE-456")


if __name__ == "__main__":
    unittest.main()
