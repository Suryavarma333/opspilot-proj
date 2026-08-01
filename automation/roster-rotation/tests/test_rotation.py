#!/usr/bin/env python3

import csv
import io
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "files" / "opspilot-roster-rotation.py"
SCHEDULE = ROOT / "files" / "roster-schedule.csv"


def selection(timestamp: str) -> tuple[str, str]:
    result = subprocess.run(
        [
            sys.executable,
            str(PROGRAM),
            "--schedule",
            str(SCHEDULE),
            "--at",
            timestamp,
            "--dry-run",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    row = next(csv.DictReader(io.StringIO(result.stdout)))
    return row["shift"], row["primary_engineer"]


CASES = {
    "2026-08-01T05:59:00": ("N", "Night Engineer"),
    "2026-08-01T06:00:00": ("M", "Morning Engineer"),
    "2026-08-01T13:59:00": ("M", "Morning Engineer"),
    "2026-08-01T14:00:00": ("E", "Evening Engineer"),
    "2026-08-01T21:59:00": ("E", "Evening Engineer"),
    "2026-08-01T22:00:00": ("N", "Night Engineer"),
    "2026-08-01T23:59:00": ("N", "Night Engineer"),
    "2026-08-02T00:00:00": ("N", "Night Engineer"),
    # 08:30 UTC is exactly 14:00 IST, proving that VM timezone is irrelevant.
    "2026-08-01T08:30:00+00:00": ("E", "Evening Engineer"),
}

for timestamp, expected in CASES.items():
    actual = selection(timestamp)
    if actual != expected:
        raise SystemExit(f"{timestamp}: expected {expected}, got {actual}")

print(f"Rotation boundary tests: PASS ({len(CASES)} cases)")
