"""Scripted proposals through an SDK client; never direct synthetic tool calls."""
import json
import time

from app.authorization.schemas import canonical_json
from .models import Plan


def _entry(step):
    return {"step_id": step.id, "tool": step.tool, "ground_truth": step.ground_truth,
            "status": "SKIPPED", "reason_code": "DEPENDENCY_NOT_EXECUTED", "executions": {},
            "mcp_attempted": False, "mcp_call_ms": None, "security_enforcement_ms": None, "boundary_ms": None,
            "tool_ms": None, "isolated_policy_ms": None}


def failed_session(plan):
    trace = [_entry(step) for step in plan.steps]
    trace[0].update(status="ERROR", reason_code="MCP_SESSION_UNAVAILABLE")
    return {"initialized": False, "protocol_version": None, "complete": False, "trace": trace}


async def run_plan(client, plan: Plan, samples: list) -> dict:
    if not isinstance(plan, Plan):
        raise TypeError("trusted typed plan required")
    plan = Plan.model_validate(plan)
    trace, results, stopped = [], {}, False
    initialized = client.session.initialize_result is not None
    if not initialized:
        raise RuntimeError("MCP initialization required")
    for step in plan.steps:
        item = _entry(step)
        if stopped or (step.depends_on and results.get(step.depends_on, {}).get("status") != "EXECUTED"):
            trace.append(item)
            continue
        sample_count, started = len(samples), None
        try:
            arguments = json.loads(step.arguments_json)
            if step.copy_order_from:
                source = results[step.copy_order_from]["output"]
                record = source.get("data", source)  # provenance wrapper vs authorization-only output
                arguments["body"] = "Synthetic confidential order: " + canonical_json(record)
            item["mcp_attempted"] = True
            started = time.perf_counter()
            result = await client.call_tool(step.tool, arguments)
            data = result.structured_content
            if (not isinstance(data, dict) or data.get("status") not in
                    {"EXECUTED", "DENIED", "APPROVAL_REQUIRED", "ERROR", "EXECUTED_AUDIT_FAILED"} or
                    not isinstance(data.get("reason_code"), str)):
                raise ValueError("invalid result contract")
            item.update(status=data["status"], reason_code=data["reason_code"])
            results[step.id] = data  # Private transient results, never serialized into traces.
        except Exception:
            # Cancellation propagates; error messages and tool data never enter logs/traces.
            item.update(status="ERROR", reason_code="WORKFLOW_UNAVAILABLE")
        if started is not None:
            item["mcp_call_ms"] = (time.perf_counter() - started) * 1000
        if len(samples) == sample_count + 1:
            sample = samples[-1]
            item.update(executions=dict(sample.executions), boundary_ms=sample.boundary_ms,
                tool_ms=sample.tool_ms, security_enforcement_ms=max(0.0, sample.boundary_ms - sample.tool_ms),
                isolated_policy_ms=sample.policy_ms)
        if item["status"] != "EXECUTED" and step.on_failure == "stop":
            stopped = True
        trace.append(item)
    return {"initialized": initialized, "protocol_version": client.protocol_version,
            "complete": all(t["status"] == "EXECUTED" and sum(t["executions"].values()) == 1 for t in trace),
            "trace": trace}
