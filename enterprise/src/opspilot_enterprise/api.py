"""Signed FastAPI ingress for alerts, status, and approval-gated remediation."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .config import Settings, load_settings
from .factory import build_ledger, build_remediation
from .ledger import IncidentLedger
from .models import AlertEvent, RemediationRequest
from .remediation import RemediationDenied, RemediationEngine
from .security import verify_hmac_request

logger = logging.getLogger(__name__)


@dataclass
class AppState:
    settings: Settings
    ledger: IncidentLedger
    remediation: RemediationEngine


def _authenticate(request: Request, body: bytes, state: AppState) -> None:
    if not verify_hmac_request(
        body,
        request.headers,
        state.settings.webhook_hmac_secret.get_secret_value(),
        replay_seconds=state.settings.webhook_replay_seconds,
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or load_settings()
    ledger = build_ledger(configured)
    state = AppState(
        settings=configured,
        ledger=ledger,
        remediation=build_remediation(configured, ledger),
    )
    app = FastAPI(
        title="OpsPilot Enterprise",
        version="1.0.0",
        docs_url=None if configured.environment == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if configured.environment == "production" else "/openapi.json",
    )
    app.state.opspilot = state

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        state.ledger.initialize()
        return {"status": "ready"}

    @app.post("/v1/alerts", status_code=status.HTTP_202_ACCEPTED)
    async def receive_alert(request: Request) -> JSONResponse:
        body = await request.body()
        _authenticate(request, body, state)
        try:
            payload = json.loads(body)
            alert = AlertEvent.model_validate(payload)
        except (json.JSONDecodeError, ValidationError) as error:
            raise HTTPException(status_code=422, detail="invalid alert payload") from error
        inserted, job_id = state.ledger.register_alert(alert)
        logger.info(
            "alert accepted",
            extra={
                "context": {
                    "alert_id": alert.alert_id,
                    "inserted": inserted,
                    "job_id": job_id,
                }
            },
        )
        return JSONResponse(
            status_code=202,
            content={
                "status": "accepted",
                "alert_id": alert.alert_id,
                "new_incident": inserted,
                "job_id": job_id,
                "duplicate_occurrence": job_id is None,
            },
        )

    @app.get("/v1/incidents/{alert_id}")
    async def get_incident(alert_id: str, request: Request) -> dict[str, Any]:
        _authenticate(request, b"", state)
        incident = state.ledger.get_incident(alert_id)
        if not incident:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident

    @app.post("/v1/remediations")
    async def remediate(request: Request) -> dict[str, Any]:
        body = await request.body()
        _authenticate(request, body, state)
        try:
            remediation_request = RemediationRequest.model_validate_json(body)
            result = state.remediation.execute(remediation_request)
        except ValidationError as error:
            raise HTTPException(status_code=422, detail="invalid remediation request") from error
        except RemediationDenied as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        return result.model_dump(mode="json")

    return app
