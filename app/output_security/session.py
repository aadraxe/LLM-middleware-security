"""Trusted host adapter: internal loop output cannot bypass the release guard."""
from collections import Counter

from app.agent.llm.loop import Outcome, run_agent
from .guard import (FinalResponseGuard, InMemoryOutputAuditSink, OutputDecision,
                    local_recipient_policy)


class CustomerOutcome(Outcome):
    output_decision: OutputDecision
    model_text_released: bool
    output_enforcement_ms: float
    response_complete: bool
    tool_execution_counts: dict[str, int]


async def run_protected_agent(application, actor, planner, customer, recipient, *, limits=None,
                              output_policy=None, output_audit=None):
    """Host-only composition; no recipient or policy is read from model/customer.

    The raw loop is internal experiment machinery. Only the guarded value leaves
    this adapter. A returned fixed replacement never implies tool rollback.
    """
    try:
        connection, samples, context = application.connect_bound(actor)
        guard = FinalResponseGuard(application.store,
            local_recipient_policy() if output_policy is None else output_policy,
            InMemoryOutputAuditSink() if output_audit is None else output_audit)
        async with connection as client:
            outcome = await run_agent(client, planner, customer, samples, limits=limits)
        released = await guard.release(outcome.final_answer if outcome.status == "FINAL" else None,
                                       context, recipient)
        executions = Counter()
        for event in outcome.trace:
            executions.update(event["executions"])
        return CustomerOutcome(**outcome.model_dump(), final_answer=released.text,
            output_decision=released.decision, model_text_released=released.model_text_released,
            output_enforcement_ms=released.enforcement_ms,
            response_complete=outcome.status == "FINAL" and released.model_text_released,
            tool_execution_counts=dict(executions))
    except Exception:
        # Do not return raw Outcome or provider/argument-bearing exception text.
        raise RuntimeError("agent session unavailable") from None
