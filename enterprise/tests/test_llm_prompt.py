from __future__ import annotations

import json

import httpx
from pydantic import SecretStr

from opspilot_enterprise.llm import (
    BharatRouterLLMClient,
    deterministic_fallback,
    enforce_deterministic_findings,
)
from opspilot_enterprise.models import HostTelemetry, SyntheticFinding
from opspilot_enterprise.prompt import (
    MASTER_SYSTEM_PROMPT,
    build_evidence_envelope,
    build_user_prompt,
    rca_json_schema,
)


def synthetic_host() -> HostTelemetry:
    return HostTelemetry(
        node="test-node",
        evidence_sha256="a" * 64,
        synthetic_findings=[
            SyntheticFinding(
                pid=4242,
                classification="confirmed",
                confidence="high",
                tool="stress-ng",
                exact_command="/usr/bin/stress-ng --cpu 4 --timeout 2m",
                signature="known-tool:stress-ng",
                rationale="explicit synthetic workload generator",
                parent_chain=[4000, 1],
            )
        ],
    )


def test_prompt_has_untrusted_boundary_and_four_part_contract(cpu_alert, empty_history) -> None:
    envelope = build_evidence_envelope(
        cpu_alert, host=synthetic_host(), network=None, history=empty_history
    )
    prompt, digest = build_user_prompt(envelope)
    assert "BEGIN_UNTRUSTED_EVIDENCE" in prompt
    assert "END_UNTRUSTED_EVIDENCE" in prompt
    assert len(digest) == 64
    assert "STRICT FOUR-PART OUTPUT" in MASTER_SYSTEM_PROMPT


def test_strict_schema_marks_every_object_property_required() -> None:
    schema = rca_json_schema()

    def check(node) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("properties"), dict):
                assert set(node["required"]) == set(node["properties"])
                assert node["additionalProperties"] is False
            for value in node.values():
                check(value)
        elif isinstance(node, list):
            for value in node:
                check(value)

    check(schema)


def test_deterministic_fallback_calls_stress_manual_load(cpu_alert, empty_history) -> None:
    rca = deterministic_fallback(
        cpu_alert, empty_history, synthetic_host(), reason="provider unavailable"
    )
    assert rca.summary.classification == "manually_injected_load"
    assert rca.summary.confidence == "high"
    assert rca.summary.exact_injector_command == "/usr/bin/stress-ng --cpu 4 --timeout 2m"


def test_model_cannot_override_confirmed_synthetic_finding(cpu_alert, empty_history) -> None:
    organic = deterministic_fallback(cpu_alert, empty_history, None, reason="missing")
    reconciled = enforce_deterministic_findings(organic, synthetic_host())
    assert reconciled.summary.classification == "manually_injected_load"
    assert reconciled.summary.synthetic_load_detected


def test_bharatrouter_client_parses_strict_rca_and_route(cpu_alert, empty_history) -> None:
    expected = deterministic_fallback(cpu_alert, empty_history, None, reason="fixture")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer br-test-key"
        assert body["data_policy"] == "india_only"
        assert body["response_format"]["type"] == "json_schema"
        return httpx.Response(
            200,
            headers={"x-br-provider": "krutrim"},
            json={
                "choices": [
                    {"message": {"role": "assistant", "content": expected.model_dump_json()}}
                ]
            },
        )

    client = BharatRouterLLMClient(
        api_key=SecretStr("br-test-key"),
        model="qwen2.5-7b-instruct",
        transport=httpx.MockTransport(handler),
    )
    result = client.analyze(
        alert=cpu_alert,
        history=empty_history,
        host=None,
        user_prompt="evidence",
        prompt_sha256="b" * 64,
    )
    assert not result.fallback_used
    assert result.route == "krutrim"
    assert result.rca.schema_version == "opspilot.rca.v2"


def test_bharatrouter_falls_back_to_json_object_when_route_rejects_schema(
    cpu_alert, empty_history
) -> None:
    expected = deterministic_fallback(cpu_alert, empty_history, None, reason="fixture")
    formats: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        response_format = body["response_format"]["type"]
        formats.append(response_format)
        if response_format == "json_schema":
            return httpx.Response(
                400,
                json={"error": {"code": "unsupported_response_format"}},
            )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": expected.model_dump_json()}}]},
        )

    client = BharatRouterLLMClient(
        api_key=SecretStr("br-test-key"),
        model="model-without-schema",
        transport=httpx.MockTransport(handler),
    )
    result = client.analyze(
        alert=cpu_alert,
        history=empty_history,
        host=None,
        user_prompt="evidence",
        prompt_sha256="f" * 64,
    )
    assert formats == ["json_schema", "json_object"]
    assert not result.fallback_used
