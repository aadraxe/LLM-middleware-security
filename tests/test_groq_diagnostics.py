"""Metadata-only error classification: all HTTP interactions use MockTransport."""
import asyncio
import csv
import json

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.agent.llm.contracts import PlannerRequest
from app.agent.llm.groq import GroqConfig, GroqPlanner
from app.agent.llm.live import run_evaluation, write_reports
from app.agent.llm.live_scenarios import MODEL, scenarios
from app.agent.llm.contracts import Limits
from app.agent.llm.usage import ProviderExchange

SECRET = "synthetic-sensitive-response-prompt-arguments-key"


def planner(handler):
    return GroqPlanner(GroqConfig(enabled=True, model=MODEL, api_key=SecretStr("synthetic-auth-key")),
                       transport=httpx.MockTransport(handler))


def reply():
    return {"choices": [{"finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
        "tool_calls": [{"id": "call-1", "type": "function", "function": {
            "name": "get_order", "arguments": '{"order_id":"order-a"}'}}]}}]}


def propose(client):
    return asyncio.run(client.propose(PlannerRequest(customer=SECRET, tools=())))


@pytest.mark.parametrize("status,hint", [(400, "invalid_request"), (401, "authentication_error"),
    (403, "permission_error"), (404, "not_found"), (429, "rate_limited"), (500, "server_error")])
def test_http_statuses_are_preserved_without_raw_body_or_retry(status, hint, caplog, capsys):
    import logging
    caplog.set_level(logging.DEBUG)
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(status, json={"error": {"message": SECRET, "code": SECRET,
                                                     "failed_generation": {"arguments": SECRET}}})
    client = planner(handle)
    with pytest.raises(RuntimeError, match="^planner unavailable$") as error: propose(client)
    assert len(calls) == 1
    event = client.exchanges[0]
    assert event.http_status == status and event.diagnostic_category == "http_error"
    assert event.provider_error_category == hint
    text = event.model_dump_json() + str(error.value) + caplog.text + str(capsys.readouterr())
    assert SECRET not in text and "synthetic-auth-key" not in text


@pytest.mark.parametrize("code,hint", [("model_not_found", "model_unavailable"), ("unsupported_model", "model_unavailable"),
    ("model_decommissioned", "model_unavailable"), ("tool_use_failed", "tool_generation_failed"),
    ("insufficient_quota", "quota_exceeded"), ("invalid_api_key", "authentication_error")])
def test_specific_error_codes_map_only_to_fixed_hints(code, hint):
    client = planner(lambda r: httpx.Response(400, json={"error": {"code": code, "type": "invalid_request_error", "message": SECRET}}))
    with pytest.raises(RuntimeError): propose(client)
    assert client.exchanges[0].provider_error_category == hint


@pytest.mark.parametrize("kind,category", [("json", "invalid_json"), ("choices", "invalid_response_structure"),
    ("role", "invalid_response_structure"), ("parallel", "invalid_tool_call"),
    ("arguments", "invalid_tool_call"), ("duplicate_arguments", "invalid_tool_call"),
    ("mixed_text", "invalid_tool_call"), ("truncated", "truncated_response"),
    ("error", "provider_error"), ("final", "invalid_final_answer"), ("oversize", "response_limit")])
def test_success_status_does_not_hide_schema_and_parsing_failures(kind, category):
    def handle(request):
        data = reply()
        if kind == "json": return httpx.Response(200, text="not JSON " + SECRET)
        if kind == "oversize": return httpx.Response(200, content=b'x' * 65537)
        choice, message = data["choices"][0], data["choices"][0]["message"]
        if kind == "choices": data = {"private": SECRET}
        if kind == "role": message["role"] = "system"
        if kind == "parallel": message["tool_calls"] *= 2
        if kind == "arguments": message["tool_calls"][0]["function"]["arguments"] = SECRET
        if kind == "duplicate_arguments": message["tool_calls"][0]["function"]["arguments"] = '{"a":1,"a":2}'
        if kind == "mixed_text": message["content"] = SECRET
        if kind == "truncated": choice["finish_reason"] = "length"
        if kind == "error": data = {"error": {"type": "invalid_request_error", "message": SECRET}}
        if kind == "final": data = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": None}}]}
        return httpx.Response(200, json=data)
    client = planner(handle)
    with pytest.raises(RuntimeError): propose(client)
    assert client.exchanges[0].http_status == 200 and client.exchanges[0].diagnostic_category == category
    assert SECRET not in client.exchanges[0].model_dump_json()


@pytest.mark.parametrize("exception,category", [(httpx.ConnectError, "transport_error"), (httpx.ReadError, "transport_error"),
    (httpx.ConnectTimeout, "timeout"), (httpx.ReadTimeout, "timeout")])
def test_transport_and_httpx_timeout_are_distinct(exception, category):
    def fail(request): raise exception(SECRET, request=request)
    client = planner(fail)
    with pytest.raises(RuntimeError): propose(client)
    assert client.exchanges[0].diagnostic_category == category and client.exchanges[0].http_status is None


def test_request_failures_before_http_are_observable_without_secret_exception():
    client = planner(lambda r: pytest.fail("must not contact transport"))
    with pytest.raises(RuntimeError, match="^planner unavailable$"):
        asyncio.run(client.propose({"private": SECRET}))
    assert client.exchanges[0].diagnostic_category == "request_invalid" and not client.exchanges[0].request_attempted
    with pytest.raises(RuntimeError):
        asyncio.run(client.propose(PlannerRequest(customer=SECRET * 10000, tools=())))
    assert client.exchanges[1].diagnostic_category == "request_limit" and client.exchanges[1].http_status is None


def test_successful_structured_tool_call_keeps_contract_and_records_success():
    requests = []
    def handle(request):
        requests.append(json.loads(request.content))
        data = reply()
        data["usage"] = {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
        return httpx.Response(200, json=data)
    client = planner(handle)
    decision = propose(client)
    assert decision.tool.name == "get_order" and decision.tool.arguments_json == '{"order_id":"order-a"}'
    assert requests[0]["model"] == MODEL and requests[0]["parallel_tool_calls"] is False
    assert requests[0]["tool_choice"] == "auto" and requests[0]["max_completion_tokens"] == 1024
    assert client.exchanges[0].http_status == 200 and client.exchanges[0].diagnostic_category == "success"
    assert client.exchanges[0].usage.total_tokens == 5


def test_real_mcp_discovered_schemas_and_tool_result_roles_are_documented_shape():
    requests = []
    def handle(request):
        body = json.loads(request.content)
        requests.append(body)
        assert {t["function"]["name"] for t in body["tools"]} == {"get_order", "send_email", "issue_refund"}
        for tool in body["tools"]:
            schema = tool["function"]["parameters"]
            assert tool["type"] == "function" and schema["type"] == "object" and schema["additionalProperties"] is False
            assert "order_id" in schema["properties"] and "order_id" in schema["required"]
        if len(requests) == 1: return httpx.Response(200, json=reply())
        assert [m["role"] for m in body["messages"]] == ["system", "user", "assistant", "tool"]
        assert body["messages"][-1]["tool_call_id"] == "call-1"
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "Done"}}]})
    report = asyncio.run(run_evaluation(scenarios()[:1], Limits(max_steps=4), 2, lambda: planner(handle), evidence_source="offline_fixture"))
    assert report["rows"][0]["execution_counts"] == {"get_order": 1} and len(requests) == 2
    assert all(d["diagnostic_category"] == "success" for d in report["rows"][0]["provider_diagnostics"])


def test_new_evaluation_json_csv_has_safe_diagnostics_and_zero_mcp_on_401(tmp_path):
    report = asyncio.run(run_evaluation(scenarios()[:1], Limits(), 2,
        lambda: planner(lambda r: httpx.Response(401, json={"error": {"code": "invalid_api_key", "message": SECRET}})),
        evidence_source="offline_fixture"))
    row = report["rows"][0]
    assert row["final_response_status"] == "MODEL_UNAVAILABLE" and row["mcp_calls"] == 0 and not row["execution_counts"]
    assert row["actions"][0]["planner_failure_category"] == "planner_error"
    assert row["provider_diagnostics"][0]["http_status"] == 401
    output = write_reports(report, tmp_path)
    with (output / "tasks.csv").open(newline="", encoding="utf-8") as handle:
        data = next(csv.DictReader(handle))
    assert json.loads(data["provider_diagnostics"])[0]["provider_error_category"] == "authentication_error"
    with (output / "actions.csv").open(newline="", encoding="utf-8") as handle:
        assert next(csv.DictReader(handle))["planner_failure_category"] == "planner_error"
    assert SECRET not in "".join(p.read_text() for p in output.iterdir())


def test_outer_planner_deadline_and_provider_cancellation_are_separate():
    async def scenario():
        async def slow(request): await asyncio.sleep(10)
        client = planner(slow)
        report = await run_evaluation(scenarios()[:1], Limits(model_timeout_seconds=.01), 1, lambda: client, evidence_source="offline_fixture")
        row = report["rows"][0]
        assert row["actions"][0]["planner_failure_category"] == "timeout"
        assert row["provider_diagnostics"][0]["diagnostic_category"] == "cancelled"
        assert row["mcp_calls"] == 0 and not row["execution_counts"]
    asyncio.run(scenario())


def test_unknown_error_hints_cannot_exfiltrate_provider_strings():
    client = planner(lambda r: httpx.Response(400, json={"error": {"type": SECRET, "code": {"private": SECRET}, "message": SECRET}}))
    with pytest.raises(RuntimeError): propose(client)
    assert client.exchanges[0].provider_error_category == "invalid_request"
    with pytest.raises(ValidationError): ProviderExchange(request_attempted=True, provider_error_category=SECRET)


def test_http_404_alone_does_not_claim_model_is_unsupported():
    client = planner(lambda r: httpx.Response(404, text=SECRET))
    with pytest.raises(RuntimeError): propose(client)
    assert client.exchanges[0].provider_error_category == "not_found"


def test_default_transport_failure_reaches_serialized_json_without_network(monkeypatch, tmp_path):
    # Exercise the real-provider/default-transport branch while replacing the
    # complete HTTP handler with a local fixture. No socket/network operation.
    calls = []
    fixture = httpx.MockTransport(lambda request: httpx.Response(403, json={
        "error": {"type": "permission_error", "message": SECRET}}))
    async def handle(_transport, request):
        calls.append(request)
        return await fixture.handle_async_request(request)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    client = GroqPlanner(GroqConfig(enabled=True, model=MODEL, api_key=SecretStr("synthetic-auth-key")))
    assert client.uses_default_transport
    report = asyncio.run(run_evaluation(scenarios()[:1], Limits(), 2, lambda: client,
                                       evidence_source="live_provider"))
    output = write_reports(report, tmp_path)
    saved = json.loads((output / "evaluation.json").read_text(encoding="utf-8"))
    assert len(calls) == 1 and saved["rows"][0]["final_response_status"] == "MODEL_UNAVAILABLE"
    assert saved["rows"][0]["mcp_calls"] == 0 and saved["rows"][0]["execution_counts"] == {}
    for diagnostics in (saved["rows"][0]["provider_diagnostics"], saved["summary"]["provider_diagnostics"]):
        assert diagnostics[0]["http_status"] == 403
        assert diagnostics[0]["diagnostic_category"] == "http_error"
        assert diagnostics[0]["provider_error_category"] == "permission_error"
    assert SECRET not in (output / "evaluation.json").read_text() and "synthetic-auth-key" not in json.dumps(saved)
