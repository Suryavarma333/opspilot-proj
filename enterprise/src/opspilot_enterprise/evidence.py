"""Atomic, compressed, content-addressed evidence persistence."""

from __future__ import annotations

import gzip
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .security import canonical_json, evidence_hash, redact_json


@dataclass(frozen=True)
class StoredEvidence:
    path: Path
    sha256: str
    size_bytes: int


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def _safe_alert_id(alert_id: str) -> str:
        return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in alert_id)[:128]

    def write(self, alert_id: str, payload: dict[str, Any]) -> StoredEvidence:
        sanitized = redact_json(payload)
        digest = evidence_hash(sanitized)
        now = datetime.now(UTC)
        directory = self.root / now.strftime("%Y/%m/%d")
        directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        filename = f"{self._safe_alert_id(alert_id)}.{digest}.json.gz"
        destination = directory / filename
        if destination.exists():
            return StoredEvidence(destination, digest, destination.stat().st_size)

        raw = canonical_json(sanitized)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".opspilot-", dir=directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as raw_handle:
                with gzip.GzipFile(fileobj=raw_handle, mode="wb", mtime=0) as compressed:
                    compressed.write(raw)
                raw_handle.flush()
                os.fsync(raw_handle.fileno())
            os.chmod(temporary, 0o640)
            os.replace(temporary, destination)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary.exists():
                temporary.unlink()
        return StoredEvidence(destination, digest, destination.stat().st_size)
