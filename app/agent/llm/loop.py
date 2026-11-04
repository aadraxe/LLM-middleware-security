"""Internal bounded planner loop; external answers require output_security.

Historical evaluators use internal Outcome for metadata experiments. It is not
an outward response contract. run_customer_task always applies final egress.
"""
import asyncio
import hashlib
import time

from pydantic import Field
from app.authorization.schemas import (EmailArguments, JsonValue, OrderArguments, ReasonCode, RefundArguments,
                                       StrictModel, canonical_json)
from .contracts import Decision, Limits, Planner, PlannerRequest, ToolDefinition, ToolTurn, json_object

SCHEMAS = {"get_order": OrderArguments, "send_email": EmailArguments, "issue_refund": RefundArguments}


class ToolResult(StrictModel):
    status: str
    reason_code: ReasonCode
    output: JsonValue = None


class Outcome(StrictModel):
    status: str
    model_calls: int
    mcp_calls: int
    discovered_tools: tuple[str, ...]
    trace: tuple[dict[str, JsonValue], ...]
    # Final model text remains untrusted, transient host output, never exported.
    final_answer: str | None = Field(default=None, exclude=True, repr=False)


async def bounded(awaitable, timeout):
    started = time.perf_counter()
    value = await asyncio.wait_for(awaitable, timeout)
    task = asyncio.current_task()
    if task is not None and task.cancelling():
        raise asyncio.CancelledError()
    if time.perf_counter() - started > timeout:
        raise TimeoutError("deadline exceeded")
    return value


async def run_agent(client, planner: Planner, customer: str, samples: list, *, limits: Limits | None = None):
    limits = Limits() if limits is None else Limits.model_validate(limits)
    trace, turns, seen, ids, model_calls, mcp_calls = [], [], set(), set(), 0, 0
    names = ()
    def finish(status, answer=None):
        return Outcome(status=status, model_calls=model_calls, mcp_calls=mcp_calls,
                       discovered_tools=names, trace=tuple(trace), final_answer=answer)
    if type(customer) is not str or len(customer.encode()) > limits.max_customer_bytes:
        return finish("CUSTOMER_LIMIT")
    try:
        discovery = await bounded(client.list_tools(), limits.tool_timeout_seconds)
        if len(discovery.tools) != 3 or {t.name for t in discovery.tools} != set(SCHEMAS):
            return finish("DISCOVERY_UNAVAILABLE")
        definitions = tuple(ToolDefinition(name=t.name, description=t.description or "",
                                          input_schema_json=canonical_json(t.input_schema)) for t in discovery.tools)
        names = tuple(t.name for t in definitions)
    except Exception:
        return finish("DISCOVERY_UNAVAILABLE")
    for index in range(limits.max_steps):
        request = PlannerRequest(customer=customer, tools=definitions, turns=tuple(turns))
        if len(canonical_json(request.model_dump(mode="json")).encode()) > limits.max_prompt_bytes:
            return finish("PROMPT_LIMIT")
        event = {"step": index + 1, "model_ms": None, "tool": None, "status": "MODEL_UNAVAILABLE",
                 "reason_code": None, "mcp_call_ms": None, "security_enforcement_ms": None, "executions": {}}
        trace.append(event)
        started = time.perf_counter()
        model_calls += 1
        try:
            reply = await bounded(planner.propose(request), limits.model_timeout_seconds)
        except TimeoutError:
            event["model_ms"] = (time.perf_counter() - started) * 1000
            event["planner_failure_category"] = "timeout"
            return finish("MODEL_UNAVAILABLE")
        except Exception:
            event["model_ms"] = (time.perf_counter() - started) * 1000
            event["planner_failure_category"] = "planner_error"
            return finish("MODEL_UNAVAILABLE")
        event["model_ms"] = (time.perf_counter() - started) * 1000
        try:
            decision = Decision.model_validate(reply)
            if len(decision.model_dump_json().encode()) > limits.max_response_bytes:
                event["status"] = "RESPONSE_LIMIT"
                return finish("RESPONSE_LIMIT")
        except Exception:
            event["status"] = "INVALID_MODEL_OUTPUT"
            return finish("INVALID_MODEL_OUTPUT")
        if decision.kind == "final":
            event["status"] = "FINAL"
            return finish("FINAL", decision.answer)
        proposal = decision.tool
        if proposal.name not in SCHEMAS:
            event["status"] = "UNKNOWN_TOOL"
            return finish("UNKNOWN_TOOL")
        event["tool"] = proposal.name
        arguments = json_object(proposal.arguments_json)
        # Normalize solely for conservative repeat detection. MCP/ProtectedExecutor
        # remain the authoritative argument validator and authorizer.
        try:
            normalized = SCHEMAS[proposal.name].model_validate(arguments).model_dump(mode="json")
        except Exception:
            normalized = arguments
        fingerprint = hashlib.sha256(canonical_json([proposal.name, normalized]).encode()).hexdigest()
        if proposal.call_id in ids or fingerprint in seen:
            event["status"] = "REPEATED_CALL"
            return finish("REPEATED_CALL")
        ids.add(proposal.call_id)
        seen.add(fingerprint)  # Reserve before attempting even a denied/uncertain call.
        started, previous = time.perf_counter(), len(samples)
        mcp_calls += 1
        timed_out = False
        try:
            response = await bounded(client.call_tool(proposal.name, arguments), limits.tool_timeout_seconds)
            data = ToolResult.model_validate(response.structured_content)
            if data.status not in {"EXECUTED", "DENIED", "APPROVAL_REQUIRED", "ERROR", "EXECUTED_AUDIT_FAILED"}:
                raise ValueError("invalid result")
            if bool(response.is_error) != (data.status != "EXECUTED"):
                raise ValueError("inconsistent result")
            result_json = data.model_dump_json()
            if len(result_json.encode()) > limits.max_tool_result_bytes:
                event["status"] = "TOOL_RESULT_LIMIT"
            else:
                event.update(status=data.status, reason_code=data.reason_code)
                turns.append(ToolTurn(call=proposal, result_json=result_json))
        except TimeoutError:
            timed_out = True
            event["status"] = "TOOL_TIMEOUT"
        except Exception:
            event["status"] = "TOOL_UNAVAILABLE"
        finally:
            event["mcp_call_ms"] = (time.perf_counter() - started) * 1000
            if len(samples) == previous + 1:
                sample = samples[-1]
                event["executions"] = dict(sample.executions)
                event["security_enforcement_ms"] = max(0.0, sample.boundary_ms - sample.tool_ms)
        if event["status"] in {"TOOL_TIMEOUT", "TOOL_UNAVAILABLE"}:
            # Unknown side effects: never automatically retry or ask for a fallback path.
            return finish("TOOL_TIMEOUT" if timed_out else "TOOL_UNAVAILABLE")
        if event["status"] == "TOOL_RESULT_LIMIT":
            return finish("TOOL_RESULT_LIMIT")
    return finish("STEP_LIMIT")


async def run_customer_task(planner, customer, actor, *, limits=None, recipient=None):
    """Outward host entry point; missing trusted recipient fails output closed."""
    from app.agent.composition import create_application
    from app.output_security.session import run_protected_agent
    try:
        application = create_application()
        return await run_protected_agent(application, actor, planner, customer, recipient, limits=limits)
    except Exception:
        # Do not invent zero-execution metrics for an uncertain session failure.
        # Caller cancellation propagates and no retry/new session is attempted.
        raise RuntimeError("agent session unavailable") from None
