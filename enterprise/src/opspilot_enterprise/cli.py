"""Operational entry points for API, workers, poller, and controlled remediation."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import uvicorn

from .api import create_app
from .config import load_settings
from .factory import (
    build_flap_detector,
    build_ledger,
    build_orchestrator,
    build_remediation,
    build_router,
)
from .logging import configure_logging
from .models import RemediationRequest
from .worker import IncidentWorker


def api_main() -> None:
    settings = load_settings()
    configure_logging(settings.log_level)
    uvicorn.run(
        create_app(settings),
        host=settings.api_host,
        port=settings.api_port,
        proxy_headers=False,
        server_header=False,
        access_log=True,
    )


def worker_main() -> None:
    settings = load_settings()
    configure_logging(settings.log_level)
    ledger = build_ledger(settings)
    worker = IncidentWorker(
        ledger=ledger,
        orchestrator=build_orchestrator(settings, ledger),
        lease_seconds=settings.worker_lease_seconds,
    )
    worker.run_forever(settings.worker_poll_seconds)


def router_poller_main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=30)
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args()
    settings = load_settings()
    configure_logging(settings.log_level)
    ledger = build_ledger(settings)
    router = build_router(settings)
    if not router or not settings.router_device_id:
        raise SystemExit("router base URL, API key, and device ID must be configured")
    detector = build_flap_detector(settings, ledger)
    while True:
        snapshot = router.fetch_interfaces(settings.router_device_id)
        alerts, assessments = detector.ingest(snapshot)
        print(
            json.dumps(
                {
                    "collected_at": snapshot.collected_at.isoformat(),
                    "alerts": [item.model_dump(mode="json") for item in alerts],
                    "assessments": {
                        name: value.model_dump(mode="json") for name, value in assessments.items()
                    },
                },
                default=str,
            )
        )
        if arguments.once:
            return
        time.sleep(max(5, arguments.interval))


def remediate_main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("request", help="path to a JSON RemediationRequest or '-' for stdin")
    arguments = parser.parse_args()
    if arguments.request == "-":
        raw = sys.stdin.read()
    else:
        with open(arguments.request, encoding="utf-8") as request_file:
            raw = request_file.read()
    settings = load_settings()
    configure_logging(settings.log_level)
    ledger = build_ledger(settings)
    result = build_remediation(settings, ledger).execute(
        RemediationRequest.model_validate_json(raw)
    )
    print(result.model_dump_json(indent=2))


def import_legacy_main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", type=Path, help="path to the legacy incidents.json")
    arguments = parser.parse_args()
    settings = load_settings()
    configure_logging(settings.log_level)
    result = build_ledger(settings).import_legacy_json(arguments.ledger)
    print(json.dumps(result, sort_keys=True))
