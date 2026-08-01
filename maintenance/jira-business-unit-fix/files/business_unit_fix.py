#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


FIELD_ENV = "OPSPILOT_JIRA_BUSINESS_UNIT_FIELD_ID"
CONSTANT_MARKER = "# OpsPilot Jira Business Unit fix v1.0.0"
FUNCTION_MARKER = "# Validate the required Jira Business Unit option before dispatch."
PAYLOAD_MARKER = "# Required Jira Business Unit field."


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def api_get(url: str, email: str, token: str) -> dict[str, Any]:
    encoded = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {encoded}",
            "User-Agent": "OpsPilot-Business-Unit-Fix/1.0.0",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise RuntimeError("Jira metadata response exceeded the safety limit")
            data = json.loads(body.decode("utf-8"))
    except HTTPError as error:
        detail = error.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"Jira metadata request returned HTTP {error.code}: {detail}") from error
    except URLError as error:
        raise RuntimeError(f"Jira metadata request failed: {error.reason}") from error
    if not isinstance(data, dict):
        raise RuntimeError("Jira metadata response was not a JSON object")
    return data


def issue_type_id(config: dict[str, str]) -> str:
    base_url = config["OPSPILOT_JIRA_URL"].rstrip("/")
    project_key = config["OPSPILOT_JIRA_PROJECT_KEY"].upper()
    requested_type = config["OPSPILOT_JIRA_ISSUE_TYPE"]
    project = api_get(
        f"{base_url}/rest/api/3/project/{quote(project_key, safe='')}",
        config["OPSPILOT_JIRA_EMAIL"],
        config["OPSPILOT_JIRA_API_TOKEN"],
    )
    for item in project.get("issueTypes", []):
        if isinstance(item, dict) and str(item.get("name", "")).casefold() == requested_type.casefold():
            value = str(item.get("id", ""))
            if value:
                return value
    raise RuntimeError(f"Jira project {project_key} does not expose issue type {requested_type}")


def business_unit_metadata(config: dict[str, str]) -> dict[str, Any]:
    base_url = config["OPSPILOT_JIRA_URL"].rstrip("/")
    project_key = config["OPSPILOT_JIRA_PROJECT_KEY"].upper()
    field_id = config[FIELD_ENV]
    type_id = issue_type_id(config)
    start_at = 0
    while True:
        endpoint = (
            f"{base_url}/rest/api/3/issue/createmeta/"
            f"{quote(project_key, safe='')}/issuetypes/{quote(type_id, safe='')}"
            f"?startAt={start_at}&maxResults=100"
        )
        page = api_get(
            endpoint,
            config["OPSPILOT_JIRA_EMAIL"],
            config["OPSPILOT_JIRA_API_TOKEN"],
        )
        # Jira's Get create field metadata endpoint returns its page in
        # ``fields``.  ``values`` is used by several other Jira paginated
        # endpoints, but not this one.
        fields = page.get("fields", [])
        if not isinstance(fields, list):
            raise RuntimeError("Jira create metadata did not contain a field list")
        for field in fields:
            if not isinstance(field, dict):
                continue
            identifier = str(field.get("fieldId") or field.get("key") or "")
            if identifier == field_id:
                return field
        if page.get("isLast") is True or not fields:
            break
        start_at += len(fields)
        total = page.get("total")
        if isinstance(total, int) and start_at >= total:
            break
    raise RuntimeError(
        f"{field_id} was not returned by Jira create metadata for "
        f"{project_key} / {config['OPSPILOT_JIRA_ISSUE_TYPE']}"
    )


def available_options(field: dict[str, Any]) -> tuple[list[tuple[str, str]], bool]:
    schema = field.get("schema") if isinstance(field.get("schema"), dict) else {}
    multiple = schema.get("type") == "array"
    raw_options = field.get("allowedValues")
    if not isinstance(raw_options, list):
        raw_options = []
    options: list[tuple[str, str]] = []
    for item in raw_options:
        if not isinstance(item, dict):
            continue
        if item.get("children"):
            raise RuntimeError("Cascading Business Unit options require a Jira administrator review")
        option_id = str(item.get("id", ""))
        label = str(item.get("value") or item.get("name") or "").strip()
        if re.fullmatch(r"[0-9]{1,30}", option_id) and label:
            options.append((option_id, label))
    return options, multiple


def patch_backend(source: str) -> str:
    if CONSTANT_MARKER not in source:
        anchor_match = re.search(
            r'^JIRA_ISSUE_TYPE = os\.environ\.get\('
            r'"OPSPILOT_JIRA_ISSUE_TYPE", "[^"]+"\)\.strip\(\)\n',
            source,
            flags=re.MULTILINE,
        )
        if anchor_match is None:
            raise RuntimeError("Installed backend does not match the supported OpsPilot v0.9 source")
        addition = (
            f"{CONSTANT_MARKER}\n"
            + 'JIRA_BUSINESS_UNIT_FIELD_ID = os.environ.get(\n'
            + f'    "{FIELD_ENV}", ""\n'
            + ').strip()\n'
            + 'JIRA_BUSINESS_UNIT_OPTION_ID = os.environ.get(\n'
            + '    "OPSPILOT_JIRA_BUSINESS_UNIT_OPTION_ID", ""\n'
            + ').strip()\n'
            + 'JIRA_BUSINESS_UNIT_MULTIPLE = os.environ.get(\n'
            + '    "OPSPILOT_JIRA_BUSINESS_UNIT_MULTIPLE", "false"\n'
            + ').strip().lower() == "true"\n'
        )
        source = source[: anchor_match.end()] + addition + source[anchor_match.end() :]

    if FUNCTION_MARKER not in source:
        anchor = "def _create_jira_issue(draft: dict[str, Any]) -> dict[str, Any]:\n    project = _jira_project()\n"
        addition = (
            "def _create_jira_issue(draft: dict[str, Any]) -> dict[str, Any]:\n"
            f"    {FUNCTION_MARKER}\n"
            "    if not re.fullmatch(r\"customfield_[0-9]{1,30}\", JIRA_BUSINESS_UNIT_FIELD_ID):\n"
            "        raise RuntimeError(\"Jira Business Unit field is not configured\")\n"
            "    if not re.fullmatch(r\"[0-9]{1,30}\", JIRA_BUSINESS_UNIT_OPTION_ID):\n"
            "        raise RuntimeError(\"Jira Business Unit option is not configured\")\n"
            "    project = _jira_project()\n"
        )
        if anchor not in source:
            raise RuntimeError("Could not locate the Jira create function in the installed backend")
        source = source.replace(anchor, addition, 1)

    if PAYLOAD_MARKER not in source:
        anchor = '                "labels": ["opspilot", "noc-automation", draft["severity"].lower()],\n'
        addition = (
            anchor
            + f"                {PAYLOAD_MARKER}\n"
            + '                JIRA_BUSINESS_UNIT_FIELD_ID: (\n'
            + '                    [{"id": JIRA_BUSINESS_UNIT_OPTION_ID}]\n'
            + '                    if JIRA_BUSINESS_UNIT_MULTIPLE\n'
            + '                    else {"id": JIRA_BUSINESS_UNIT_OPTION_ID}\n'
            + '                ),\n'
        )
        if anchor not in source:
            raise RuntimeError("Could not locate the Jira fields payload in the installed backend")
        source = source.replace(anchor, addition, 1)

    compile(source, "opspilot_dashboard_agent.py", "exec")
    return source


def atomic_write(path: Path, text: str) -> None:
    original = path.stat()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, stat.S_IMODE(original.st_mode))
        os.chown(temporary_name, original.st_uid, original.st_gid)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def update_env(path: Path, option_id: str, multiple: bool) -> None:
    replacements = {
        "OPSPILOT_INTEGRATION_MODE": "draft",
        "OPSPILOT_JIRA_BUSINESS_UNIT_OPTION_ID": option_id,
        "OPSPILOT_JIRA_BUSINESS_UNIT_MULTIPLE": "true" if multiple else "false",
    }
    output: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in replacements:
            if key not in seen:
                output.append(f"{key}={replacements[key]}")
                seen.add(key)
        else:
            output.append(line)
    for key, value in replacements.items():
        if key not in seen:
            output.append(f"{key}={value}")
    atomic_write(path, "\n".join(output) + "\n")


def validate_config(config: dict[str, str]) -> None:
    required = (
        "OPSPILOT_JIRA_URL",
        "OPSPILOT_JIRA_PROJECT_KEY",
        "OPSPILOT_JIRA_ISSUE_TYPE",
        FIELD_ENV,
        "OPSPILOT_JIRA_EMAIL",
        "OPSPILOT_JIRA_API_TOKEN",
    )
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise RuntimeError("Missing Jira configuration: " + ", ".join(missing))
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,19}", config["OPSPILOT_JIRA_PROJECT_KEY"].upper()):
        raise RuntimeError("Safety stop: Jira project key is invalid")
    if not config["OPSPILOT_JIRA_ISSUE_TYPE"].strip():
        raise RuntimeError("Safety stop: Jira issue type is missing")
    if not re.fullmatch(r"customfield_[0-9]{1,30}", config[FIELD_ENV]):
        raise RuntimeError("Safety stop: Jira Business Unit field ID is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--backend", required=True, type=Path)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("This helper must be invoked through the package installer")
    config = read_env(args.config)
    validate_config(config)
    field = business_unit_metadata(config)
    if field.get("required") is not True:
        print("Note: Jira metadata currently marks Business Unit as optional.")
    options, multiple = available_options(field)
    if not options:
        raise RuntimeError(
            "Jira returned no selectable Business Unit values. Ask the Jira project "
            "administrator to review the configured field for this project and issue type."
        )

    print(
        "\nJira permits these Business Unit values for "
        f"{config['OPSPILOT_JIRA_PROJECT_KEY']} / {config['OPSPILOT_JIRA_ISSUE_TYPE']}:"
    )
    for number, (option_id, label) in enumerate(options, start=1):
        print(f"  {number}. {label} (option id {option_id})")
    while True:
        choice = input(f"Select Business Unit [1-{len(options)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            break
        print("Enter one number from the displayed list.")

    selected_id, selected_label = options[int(choice) - 1]
    updated_source = patch_backend(args.backend.read_text(encoding="utf-8"))
    atomic_write(args.backend, updated_source)
    update_env(args.config, selected_id, multiple)
    print(f"Selected Jira Business Unit: {selected_label} (option id {selected_id})")
    print(f"Configured Jira field: {config[FIELD_ENV]}")
    print("Jira writes performed: false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
