"""Explicit opt-in Groq Chat Completions adapter, using existing httpx only.

Contract verified against console.groq.com/docs/tool-use/local-tool-calling,
/docs/tool-use/overview and /docs/api-reference on 2026-11-03. No live call run.
No environment key lookup, arbitrary URL, remote MCP, built-in tool or retry.
"""
from typing import Literal

import httpx
from pydantic import Field, SecretStr
from app.authorization.schemas import StrictModel, canonical_json
from .contracts import Decision, PlannerRequest, ToolCall, json_object


class GroqConfig(StrictModel):
    enabled: Literal[True]
    api_key: SecretStr = Field(repr=False)
    model: Literal["llama-3.3-70b-versatile"]
    timeout_seconds: float = Field(default=10.0, gt=0, le=60, allow_inf_nan=False)


class GroqPlanner:
    def __init__(self, config: GroqConfig, *, transport=None):
        if not isinstance(config, GroqConfig):
            raise TypeError("explicit trusted provider configuration required")
        self._config = GroqConfig.model_validate(config)
        if not self._config.api_key.get_secret_value().strip():
            raise ValueError("provider credential required")
        self._transport = transport  # Trusted test injection; never model-selected.

    async def propose(self, request: PlannerRequest) -> Decision:
        request = PlannerRequest.model_validate(request)
        messages = [{"role": "system", "content": request.instructions}, {"role": "user", "content": request.customer}]
        for turn in request.turns:
            messages.extend([
                {"role": "assistant", "tool_calls": [{"id": turn.call.call_id, "type": "function",
                  "function": {"name": turn.call.name, "arguments": turn.call.arguments_json}}]},
                {"role": "tool", "tool_call_id": turn.call.call_id, "content": turn.result_json},
            ])
        body = {"model": self._config.model, "messages": messages, "temperature": 0,
            "tools": [{"type": "function", "function": {"name": t.name, "description": t.description,
                      "parameters": json_object(t.input_schema_json)}} for t in request.tools],
            "tool_choice": "auto", "parallel_tool_calls": False, "max_completion_tokens": 1024}
        encoded = canonical_json(body).encode()
        if len(encoded) > 131072:
            raise ValueError("provider request limit")
        try:
            async with httpx.AsyncClient(timeout=self._config.timeout_seconds, follow_redirects=False,
                                         trust_env=False, transport=self._transport) as client:
                async with client.stream("POST", "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": "Bearer " + self._config.api_key.get_secret_value(), "Content-Type": "application/json"},
                    content=encoded) as response:
                    response.raise_for_status()
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > 65536:
                            raise ValueError("provider response limit")
            data = json_object(content)
            choices = data["choices"]
            if not isinstance(choices, list) or len(choices) != 1:
                raise ValueError("single completion required")
            choice = choices[0]
            message = choice["message"]
            if message.get("role") != "assistant":
                raise ValueError("assistant response required")
            calls = message.get("tool_calls")
            if calls:
                if (choice.get("finish_reason") != "tool_calls" or not isinstance(calls, list) or len(calls) != 1
                        or message.get("content") not in (None, "")):
                    raise ValueError("one complete tool request required")
                call = calls[0]
                if set(call) != {"id", "type", "function"} or call["type"] != "function" or set(call["function"]) != {"name", "arguments"}:
                    raise ValueError("invalid structured call")
                return Decision(kind="tool", tool=ToolCall(call_id=call["id"], name=call["function"]["name"],
                                                           arguments_json=call["function"]["arguments"]))
            if choice.get("finish_reason") != "stop":
                raise ValueError("complete answer required")
            return Decision(kind="final", answer=message["content"])
        except Exception:
            # No raw provider bodies, credentials or exception chaining escape.
            raise RuntimeError("planner unavailable") from None
