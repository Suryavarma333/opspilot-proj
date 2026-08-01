import importlib.util
import pathlib
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[1] / "files" / "business_unit_fix.py"
SPEC = importlib.util.spec_from_file_location("business_unit_fix", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class BusinessUnitFixTests(unittest.TestCase):
    def test_documented_create_metadata_fields_shape_is_detected(self):
        field = {
            "fieldId": "customfield_12345",
            "required": True,
            "schema": {"type": "option"},
            "allowedValues": [{"id": "101", "value": "Infrastructure"}],
        }
        config = {
            "OPSPILOT_JIRA_URL": "https://example.atlassian.net",
            "OPSPILOT_JIRA_PROJECT_KEY": "CORE",
            "OPSPILOT_JIRA_ISSUE_TYPE": "INCIDENT",
            "OPSPILOT_JIRA_EMAIL": "bot@example.com",
            "OPSPILOT_JIRA_API_TOKEN": "not-a-real-token",
            "OPSPILOT_JIRA_BUSINESS_UNIT_FIELD_ID": "customfield_12345",
        }
        with (
            mock.patch.object(MODULE, "issue_type_id", return_value="10620"),
            mock.patch.object(
                MODULE,
                "api_get",
                return_value={
                    "fields": [field],
                    "maxResults": 50,
                    "startAt": 0,
                    "total": 1,
                },
            ),
        ):
            self.assertEqual(MODULE.business_unit_metadata(config), field)

    def test_create_metadata_fields_pagination(self):
        target = {
            "fieldId": "customfield_12345",
            "required": True,
            "allowedValues": [{"id": "201", "value": "KCC"}],
        }
        config = {
            "OPSPILOT_JIRA_URL": "https://example.atlassian.net",
            "OPSPILOT_JIRA_PROJECT_KEY": "CORE",
            "OPSPILOT_JIRA_ISSUE_TYPE": "INCIDENT",
            "OPSPILOT_JIRA_EMAIL": "bot@example.com",
            "OPSPILOT_JIRA_API_TOKEN": "not-a-real-token",
            "OPSPILOT_JIRA_BUSINESS_UNIT_FIELD_ID": "customfield_12345",
        }
        pages = [
            {"fields": [{"fieldId": "summary"}], "startAt": 0, "total": 2},
            {"fields": [target], "startAt": 1, "total": 2},
        ]
        with (
            mock.patch.object(MODULE, "issue_type_id", return_value="10620"),
            mock.patch.object(MODULE, "api_get", side_effect=pages),
        ):
            self.assertEqual(MODULE.business_unit_metadata(config), target)

    def test_single_select_options(self):
        options, multiple = MODULE.available_options(
            {
                "schema": {"type": "option"},
                "allowedValues": [
                    {"id": "101", "value": "Infrastructure"},
                    {"id": "102", "value": "Cloud"},
                ],
            }
        )
        self.assertFalse(multiple)
        self.assertEqual(options, [("101", "Infrastructure"), ("102", "Cloud")])

    def test_multi_select_shape_is_detected(self):
        options, multiple = MODULE.available_options(
            {
                "schema": {"type": "array", "items": "option"},
                "allowedValues": [{"id": "201", "name": "KCC"}],
            }
        )
        self.assertTrue(multiple)
        self.assertEqual(options, [("201", "KCC")])

    def test_backend_patch_is_idempotent(self):
        source = """import os\nimport re\nfrom typing import Any\nJIRA_ISSUE_TYPE = os.environ.get(\"OPSPILOT_JIRA_ISSUE_TYPE\", \"Server\").strip()\ndef _jira_project():\n    return {}\ndef _external_json(*args, **kwargs):\n    return 200, {\"key\": \"CORE-1\"}\ndef _jira_headers():\n    return {}\nJIRA_URL = \"https://example.atlassian.net\"\ndef _create_jira_issue(draft: dict[str, Any]) -> dict[str, Any]:\n    project = _jira_project()\n    _, response = _external_json(\n        \"POST\",\n        f\"{JIRA_URL}/rest/api/3/issue\",\n        headers=_jira_headers(),\n        payload={\n            \"fields\": {\n                \"labels\": [\"opspilot\", \"noc-automation\", draft[\"severity\"].lower()],\n            }\n        },\n    )\n    return response\n"""
        patched = MODULE.patch_backend(source)
        self.assertIn("JIRA_BUSINESS_UNIT_FIELD_ID", patched)
        self.assertNotIn('"customfield_12345":', patched)
        self.assertEqual(MODULE.patch_backend(patched), patched)


if __name__ == "__main__":
    unittest.main()
