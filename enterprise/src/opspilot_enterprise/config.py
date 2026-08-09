"""Validated environment configuration. Secrets remain SecretStr objects."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OPSPILOT_",
        env_file="/etc/opspilot-enterprise/opspilot.env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "production"] = "production"
    log_level: str = "INFO"
    state_db: Path = Path("/var/lib/opspilot-enterprise/opspilot.sqlite3")
    evidence_dir: Path = Path("/var/lib/opspilot-enterprise/evidence")
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8088, ge=1, le=65535)
    webhook_hmac_secret: SecretStr
    approval_hmac_secret: SecretStr
    webhook_replay_seconds: int = Field(default=300, ge=30, le=900)

    telemetry_command_timeout_seconds: float = Field(default=15.0, ge=1, le=120)
    telemetry_total_budget_seconds: float = Field(default=45.0, ge=5, le=300)
    telemetry_max_command_bytes: int = Field(default=512_000, ge=4_096, le=5_000_000)
    telemetry_max_processes: int = Field(default=4096, ge=16, le=65_536)
    telemetry_cpu_sample_seconds: float = Field(default=0.5, ge=0.1, le=5)

    history_window_days: int = Field(default=30, ge=7, le=30)
    flapping_window_days: int = Field(default=7, ge=1, le=30)
    flapping_cycle_threshold: int = Field(default=5, ge=2, le=100)
    history_event_limit: int = Field(default=100, ge=5, le=1000)

    bharatrouter_base_url: str = "https://api.bharatrouter.com/v1"
    bharatrouter_api_key: SecretStr | None = None
    llm_model: str = "qwen2.5-7b-instruct"
    llm_optimize: Literal["price", "latency", "uptime", "throughput", "auto"] = "uptime"
    llm_data_policy: Literal["india_only"] | None = "india_only"
    llm_timeout_seconds: float = Field(default=90, ge=5, le=300)
    llm_max_output_tokens: int = Field(default=2800, ge=600, le=8000)
    llm_response_format: Literal["json_schema", "json_object", "none"] = "json_schema"
    llm_fail_open: bool = True

    router_base_url: str | None = None
    router_api_key: SecretStr | None = None
    router_auth_header: str = "X-API-Key"
    router_device_id: str | None = None
    router_interfaces_path: str = "/v1/devices/{device_id}/interfaces"
    router_timeout_seconds: float = Field(default=10, ge=1, le=60)

    jira_base_url: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = "Incident"
    jira_user_email: str | None = None
    jira_api_token: SecretStr | None = None
    jira_bearer_token: SecretStr | None = None

    slack_webhook_url: SecretStr | None = None

    remediation_mode: Literal["disabled", "dry_run", "approval", "auto"] = "disabled"
    remediation_allowed_services: list[str] = Field(default_factory=list)
    remediation_auto_runbooks: list[str] = Field(default_factory=list)
    remediation_approval_ttl_seconds: int = Field(default=600, ge=60, le=3600)

    worker_poll_seconds: float = Field(default=1.0, ge=0.1, le=30)
    worker_lease_seconds: int = Field(default=900, ge=60, le=3600)

    allow_insecure_http: bool = False

    @field_validator("log_level")
    @classmethod
    def normalize_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid log level")
        return normalized

    @field_validator("remediation_allowed_services")
    @classmethod
    def validate_service_names(cls, values: list[str]) -> list[str]:
        import re

        for value in values:
            if not re.fullmatch(r"[A-Za-z0-9@_.:-]{1,120}(?:\.service)?", value):
                raise ValueError(f"invalid systemd service name: {value!r}")
        return sorted(set(values))

    @model_validator(mode="after")
    def validate_external_urls_and_credentials(self) -> Settings:
        urls = {
            "bharatrouter_base_url": self.bharatrouter_base_url,
            "router_base_url": self.router_base_url,
            "jira_base_url": self.jira_base_url,
            "slack_webhook_url": (
                self.slack_webhook_url.get_secret_value() if self.slack_webhook_url else None
            ),
        }
        for name, value in urls.items():
            if not value:
                continue
            parsed = urlparse(value)
            if parsed.scheme not in {"https", "http"} or not parsed.hostname:
                raise ValueError(f"{name} must be an absolute HTTP(S) URL")
            if parsed.scheme != "https" and not self.allow_insecure_http:
                raise ValueError(f"{name} must use HTTPS")

        jira_auth_count = int(bool(self.jira_api_token and self.jira_user_email)) + int(
            bool(self.jira_bearer_token)
        )
        if jira_auth_count > 1:
            raise ValueError("configure either Jira basic auth or Jira bearer auth, not both")
        if self.remediation_mode == "auto" and not self.remediation_auto_runbooks:
            raise ValueError("auto remediation requires an explicit runbook allowlist")
        return self


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
