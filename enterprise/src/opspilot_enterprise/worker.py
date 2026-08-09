"""Durable SQLite job worker for incident orchestration."""

from __future__ import annotations

import logging
import time

from .ledger import IncidentLedger
from .models import AlertEvent
from .orchestrator import OpsPilotOrchestrator
from .security import redact_text

logger = logging.getLogger(__name__)


class IncidentWorker:
    def __init__(
        self,
        *,
        ledger: IncidentLedger,
        orchestrator: OpsPilotOrchestrator,
        lease_seconds: int = 900,
        max_attempts: int = 4,
    ) -> None:
        self.ledger = ledger
        self.orchestrator = orchestrator
        self.lease_seconds = lease_seconds
        self.max_attempts = max_attempts
        self.worker_id = ledger.worker_id()

    def run_once(self) -> bool:
        job = self.ledger.claim_job(self.worker_id, self.lease_seconds)
        if not job:
            return False
        try:
            alert = AlertEvent.model_validate(job["payload"])
            result = self.orchestrator.process(alert)
            self.ledger.finish_job(int(job["id"]), self.worker_id, success=True)
            logger.info(
                "incident job completed",
                extra={
                    "context": {
                        "job_id": job["id"],
                        "alert_id": alert.alert_id,
                        "status": result.status,
                    }
                },
            )
            return True
        except Exception as error:
            safe, _ = redact_text(f"{type(error).__name__}: {error}", max_chars=2000)
            attempts = int(job["attempts"]) + 1
            retry_delay = min(300, 2 ** min(attempts, 8)) if attempts < self.max_attempts else None
            self.ledger.finish_job(
                int(job["id"]),
                self.worker_id,
                success=False,
                error=safe,
                retry_delay_seconds=retry_delay,
            )
            logger.exception(
                "incident job failed",
                extra={
                    "context": {
                        "job_id": job["id"],
                        "alert_id": job["alert_id"],
                        "attempts": attempts,
                        "retry_delay_seconds": retry_delay,
                    }
                },
            )
            return True

    def run_forever(self, poll_seconds: float = 1.0) -> None:
        logger.info("incident worker started", extra={"context": {"worker_id": self.worker_id}})
        while True:
            worked = self.run_once()
            if not worked:
                time.sleep(poll_seconds)
