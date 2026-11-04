"""Provider wire-contract fixtures via MockTransport only; no live API calls."""
import asyncio
import json

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.agent.llm.contracts import INSTRUCTIONS, PlannerRequest, ToolCall, ToolDefinition, ToolTurn
from app.agent.llm.groq import GroqConfig, GroqPlanner


def request():
    return PlannerRequest(customer="synthetic-user", tools=(ToolDefinition(name="get_order", description="Synthetic",
        input_schema_json='{"type":"object"}'),), turns=(ToolTurn(call=ToolCall(call_id="previous", name="get_order", arguments_json='{}'),
        result_json='{"status":"DENIED","reason_code":"WRONG_ROLE"}'),))


def config():
    return GroqConfig(enabled=True, model="openai/gpt-oss-120b", api_key=SecretStr("synthetic-provider-key"))


def reply(*, tool=False):
    message = {"role": "assistant", "content": "Synthetic final response"}
    if tool:
        message.update(content=None, tool_calls=[{"id": "native-call", "type": "function",
            "function": {"name": "get_order", "arguments": '{"order_id":"order-a"}'}}])
    return {"choices": [{"finish_reason": "tool_calls" if tool else "stop", "message": message}]}


@pytest.mark.parametrize("tool", [True, False])
def test_supported_structured_wire_format_and_role_separation(tool, caplog, capsys):
    import logging
    caplog.set_level(logging.DEBUG)
    seen = []
    def handle(req):
        assert str(req.url) == "https://api.groq.com/openai/v1/chat/completions"
        assert req.headers["Authorization"] == "Bearer synthetic-provider-key"
        data = json.loads(req.content)
        seen.append(data)
        assert data["model"] == "openai/gpt-oss-120b"
        assert data["parallel_tool_calls"] is False and data["tool_choice"] == "auto"
        assert data["tools"][0]["type"] == "function"
        assert [m["role"] for m in data["messages"]] == ["system", "user", "assistant", "tool"]
        assert data["messages"][0]["content"] == INSTRUCTIONS
        assert data["messages"][-1]["tool_call_id"] == "previous"
        return httpx.Response(200, json=reply(tool=tool))
    planner = GroqPlanner(config(), transport=httpx.MockTransport(handle))
    result = asyncio.run(planner.propose(request()))
    assert len(seen) == 1 and result.kind == ("tool" if tool else "final")
    assert "synthetic-provider-key" not in caplog.text + str(capsys.readouterr()) + repr(config())


@pytest.mark.parametrize("mode", ["parallel", "incomplete", "wrong_role", "bad_arguments", "duplicate_arguments", "missing", "error", "redirect", "oversize"])
def test_malformed_unavailable_provider_responses_are_sanitized_and_never_retried(mode, caplog, capsys):
    calls = []
    def handle(req):
        calls.append(req)
        if mode == "error": return httpx.Response(500, text="synthetic-private-error")
        if mode == "redirect": return httpx.Response(302, headers={"Location": "https://outside.example"})
        if mode == "oversize": return httpx.Response(200, content=b'x' * 65537)
        data = reply(tool=True)
        choice, message = data["choices"][0], data["choices"][0]["message"]
        if mode == "parallel": message["tool_calls"] *= 2
        if mode == "incomplete": choice["finish_reason"] = "length"
        if mode == "wrong_role": message["role"] = "system"
        if mode == "bad_arguments": message["tool_calls"][0]["function"]["arguments"] = "not JSON"
        if mode == "duplicate_arguments": message["tool_calls"][0]["function"]["arguments"] = '{"a":1,"a":2}'
        if mode == "missing": data = {"private": "synthetic-private-error"}
        return httpx.Response(200, json=data)
    planner = GroqPlanner(config(), transport=httpx.MockTransport(handle))
    with pytest.raises(RuntimeError, match="^planner unavailable$") as error:
        asyncio.run(planner.propose(request()))
    assert len(calls) == 1
    assert "synthetic-private" not in str(error.value) + caplog.text + str(capsys.readouterr())


def test_no_provider_is_enabled_or_selected_implicitly():
    with pytest.raises(ValidationError): GroqConfig(enabled=False, model="openai/gpt-oss-120b", api_key=SecretStr("x"))
    with pytest.raises(ValidationError): GroqConfig(enabled=True, model="unknown-model", api_key=SecretStr("x"))
    with pytest.raises(TypeError): GroqPlanner({"enabled": True})
    with pytest.raises(ValueError): GroqPlanner(config().model_copy(update={"api_key": SecretStr("")}))


def test_provider_cancellation_is_not_sanitized_into_a_retry():
    async def handle(req): raise asyncio.CancelledError()
    planner = GroqPlanner(config(), transport=httpx.MockTransport(handle))
    with pytest.raises(asyncio.CancelledError): asyncio.run(planner.propose(request()))


def test_deprecated_model_is_rejected_without_fallback():
    with pytest.raises(ValidationError):
        GroqConfig(enabled=True, model="llama-3.3-70b-versatile", api_key=SecretStr("synthetic-key"))
