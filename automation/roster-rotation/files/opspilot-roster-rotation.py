#!/usr/bin/python3
"""Maintain OpsPilot's current-on-call CSV from a validated shift schedule."""

from __future__ import annotations

import argparse
import csv
import fcntl
import io
import os
import pwd
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_SCHEDULE = Path("/etc/opspilot-dashboard/roster-schedule.csv")
DEFAULT_OUTPUT = Path(
    "/var/lib/opspilot-dashboard-agent/current-oncall.csv"
)
DEFAULT_TIMEZONE = "Asia/Kolkata"
TIME_PATTERN = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
OUTPUT_FIELDS = (
    "primary_engineer",
    "on_call",
    "team",
    "service",
    "email",
    "chat_user_id",
    "shift",
    "timezone",
    "shift_start",
    "shift_end",
    "updated_at",
)
COMPARE_FIELDS = (
    "primary_engineer",
    "on_call",
    "team",
    "service",
    "email",
    "chat_user_id",
    "shift",
    "timezone",
    "shift_start",
    "shift_end",
)


@dataclass(frozen=True)
class Shift:
    code: str
    engineer: str
    start: int
    end: int
    team: str
    service: str
    email: str
    chat_user_id: str

    def contains(self, minute: int) -> bool:
        if self.start < self.end:
            return self.start <= minute < self.end
        return minute >= self.start or minute < self.end


def parse_time(value: str, row_number: int, field: str) -> int:
    value = value.strip()
    if not TIME_PATTERN.fullmatch(value):
        raise ValueError(
            f"row {row_number}: {field} must use 24-hour HH:MM format"
        )
    hour, minute = (int(part) for part in value.split(":"))
    return hour * 60 + minute


def clock_text(minute: int) -> str:
    return f"{minute // 60:02d}:{minute % 60:02d}"


def clean_text(value: object, row_number: int, field: str) -> str:
    text = str(value or "").strip()
    if "\n" in text or "\r" in text or "\x00" in text:
        raise ValueError(f"row {row_number}: {field} contains invalid characters")
    return text


def load_schedule(path: Path) -> list[Shift]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "shift",
            "primary_engineer",
            "start_time",
            "end_time",
            "team",
            "service",
        }
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(
                "schedule is missing columns: " + ", ".join(sorted(missing))
            )

        shifts: list[Shift] = []
        for row_number, row in enumerate(reader, start=2):
            code = clean_text(row.get("shift"), row_number, "shift")
            engineer = clean_text(
                row.get("primary_engineer"), row_number, "primary_engineer"
            )
            team = clean_text(row.get("team"), row_number, "team")
            service = clean_text(row.get("service"), row_number, "service")
            if not all((code, engineer, team, service)):
                raise ValueError(
                    f"row {row_number}: shift, engineer, team, and service are required"
                )
            shifts.append(
                Shift(
                    code=code,
                    engineer=engineer,
                    start=parse_time(
                        str(row.get("start_time", "")), row_number, "start_time"
                    ),
                    end=parse_time(
                        str(row.get("end_time", "")), row_number, "end_time"
                    ),
                    team=team,
                    service=service,
                    email=clean_text(row.get("email"), row_number, "email"),
                    chat_user_id=clean_text(
                        row.get("chat_user_id"), row_number, "chat_user_id"
                    ),
                )
            )

    if not shifts:
        raise ValueError("schedule contains no shifts")

    duplicate_codes = sorted(
        code for code in {item.code for item in shifts}
        if sum(item.code == code for item in shifts) > 1
    )
    if duplicate_codes:
        raise ValueError("duplicate shift codes: " + ", ".join(duplicate_codes))

    for minute in range(24 * 60):
        matches = [shift.code for shift in shifts if shift.contains(minute)]
        if len(matches) != 1:
            detail = ", ".join(matches) if matches else "none"
            raise ValueError(
                f"schedule must cover every minute exactly once; "
                f"{clock_text(minute)} matches {detail}"
            )
    return shifts


def selected_shift(shifts: list[Shift], current: datetime) -> Shift:
    minute = current.hour * 60 + current.minute
    matches = [shift for shift in shifts if shift.contains(minute)]
    if len(matches) != 1:
        raise RuntimeError("validated schedule unexpectedly produced no unique shift")
    return matches[0]


def read_current(path: Path) -> dict[str, str] | None:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return next(csv.DictReader(handle), None)
    except (OSError, csv.Error):
        return None


def roster_row(shift: Shift, timezone_name: str, current: datetime) -> dict[str, str]:
    return {
        "primary_engineer": shift.engineer,
        "on_call": "active",
        "team": shift.team,
        "service": shift.service,
        "email": shift.email,
        "chat_user_id": shift.chat_user_id,
        "shift": shift.code,
        "timezone": timezone_name,
        "shift_start": clock_text(shift.start),
        "shift_end": clock_text(shift.end),
        "updated_at": current.isoformat(timespec="seconds"),
    }


def same_assignment(existing: dict[str, str] | None, desired: dict[str, str]) -> bool:
    return existing is not None and all(
        existing.get(field, "") == desired[field] for field in COMPARE_FIELDS
    )


def encode_row(row: dict[str, str]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerow(row)
    return output.getvalue()


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    service_account = pwd.getpwnam("opspilot")
    if os.geteuid() not in {0, service_account.pw_uid}:
        raise PermissionError(
            "roster updates must run as root or the opspilot service account"
        )
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o640)
        if os.geteuid() == 0:
            os.chown(
                temporary_name,
                service_account.pw_uid,
                service_account.pw_gid,
            )
        os.replace(temporary_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schedule", type=Path, default=DEFAULT_SCHEDULE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE)
    parser.add_argument(
        "--at",
        help="ISO timestamp used for a dry run or controlled test",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the selected CSV without changing the roster file",
    )
    return parser.parse_args()


def current_time(timezone: ZoneInfo, at: str | None) -> datetime:
    if not at:
        return datetime.now(timezone)
    parsed = datetime.fromisoformat(at)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone)
    return parsed.astimezone(timezone)


def main() -> int:
    arguments = parse_arguments()
    try:
        timezone = ZoneInfo(arguments.timezone)
        now = current_time(timezone, arguments.at)
        shifts = load_schedule(arguments.schedule)
        selected = selected_shift(shifts, now)
        desired = roster_row(selected, arguments.timezone, now)

        if arguments.dry_run:
            sys.stdout.write(encode_row(desired))
            return 0

        lock_path = arguments.output.with_name(f".{arguments.output.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            if same_assignment(read_current(arguments.output), desired):
                print(
                    f"Roster unchanged: {selected.code} / {selected.engineer} "
                    f"at {now.strftime('%Y-%m-%d %H:%M %Z')}"
                )
                return 0
            atomic_write(arguments.output, encode_row(desired))

        print(
            f"Roster updated: {selected.code} / {selected.engineer} "
            f"at {now.strftime('%Y-%m-%d %H:%M %Z')}"
        )
        return 0
    except (OSError, ValueError, KeyError, ZoneInfoNotFoundError) as error:
        print(f"Roster update failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
