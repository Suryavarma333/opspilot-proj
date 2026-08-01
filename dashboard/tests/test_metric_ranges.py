import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


class MetricRangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary_directory = tempfile.TemporaryDirectory()
        os.environ["OPSPILOT_METRICS_DB"] = str(
            Path(cls.temporary_directory.name) / "module-metrics.sqlite3"
        )
        module_path = Path(__file__).parents[1] / "files" / "opspilot_dashboard_agent.py"
        sys.path.insert(0, str(module_path.parent))
        spec = importlib.util.spec_from_file_location("opspilot_dashboard_agent_test", module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Could not load OpsPilot dashboard agent")
        cls.agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.agent)

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.pop("OPSPILOT_METRICS_DB", None)
        cls.temporary_directory.cleanup()

    def test_range_allowlist_covers_fifteen_days(self) -> None:
        self.assertEqual(
            list(self.agent.RANGE_CONFIG),
            ["15m", "30m", "1h", "3h", "6h", "12h", "24h", "7d", "15d"],
        )
        fifteen_days = 15 * 24 * 60 * 60
        self.assertEqual(self.agent.RANGE_CONFIG["15d"][0], fifteen_days)
        self.assertGreater(self.agent.METRIC_RETENTION_SECONDS, fifteen_days)

    def test_rca_command_extends_allowlist_to_172(self) -> None:
        self.assertEqual(len(self.agent.ALLOWED_COMMANDS), 172)
        self.assertIn(
            "journalctl -p 3 -xb -n 50 --no-pager",
            self.agent.ALLOWED_COMMANDS,
        )

    def test_fifteen_day_query_returns_exact_timestamp(self) -> None:
        store = self.agent.MetricStore(
            Path(self.temporary_directory.name) / "query-metrics.sqlite3"
        )
        store.record(
            {
                "cpu": {"percent": 62.4, "load_1m": 1.27},
                "memory": {"percent": 48.8},
                "disk": {"percent": 31.0},
                "network": {
                    "rx_bytes_per_second": 2048.0,
                    "tx_bytes_per_second": 1024.0,
                },
            }
        )

        result = store.query("15d")

        self.assertEqual(result["range"], "15d")
        self.assertEqual(result["step_seconds"], 2 * 60 * 60)
        self.assertEqual(len(result["samples"]), 1)
        self.assertIn("timestamp", result["samples"][0])
        self.assertEqual(result["samples"][0]["cpu"], 62.4)


if __name__ == "__main__":
    unittest.main()
