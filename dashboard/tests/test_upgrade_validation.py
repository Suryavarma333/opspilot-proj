import pathlib
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
UPGRADE_SCRIPT = REPOSITORY_ROOT / "dashboard" / "upgrade.sh"


class UpgradeValidationTests(unittest.TestCase):
    def test_validation_preserves_configured_integrations_without_demo_literals(self):
        script = UPGRADE_SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn(
            'assert data["integrations"]["jira"]["project_key"] == "OPS"',
            script,
        )
        self.assertNotIn(
            'assert data["integrations"]["google_chat"]["space"] == "NOC-Alerts"',
            script,
        )
        self.assertIn(
            "preserved_integration_configuration(current_integrations)",
            script,
        )
        self.assertIn(
            "preserved_integration_configuration(previous_integrations)",
            script,
        )
        self.assertIn(
            'assert current_integrations["external_writes_enabled"] is False',
            script,
        )
        self.assertIn(
            'integration_config_file="/etc/opspilot-dashboard/integrations.env"',
            script,
        )


if __name__ == "__main__":
    unittest.main()
