"""The sole dispatch boundary for registered tools in this local milestone."""
import asyncio
from contextlib import AbstractAsyncContextManager, AbstractContextManager, nullcontext
from datetime import datetime, timezone
import math
import time
from uuid import uuid4
from typing import Protocol
from pydantic import JsonValue

from .audit import AuthorizationAuditEvent, AuthorizationAuditSink
from .policy import PolicyDecisionPoint
from .registry import ToolRegistry
from .schemas import (AuthorizationDecision, AuthorizationRequest, ExecutionResult,
                      EmailArguments, ToolInvocation, TrustedContext, TrustedPrincipal, canonical_json, request_digest)


class ExecutionFlowGuard(Protocol):
    """Trusted extension; never selected or configured by a tool invocation."""
    def session(self, principal: TrustedPrincipal) -> AbstractAsyncContextManager: ...
    def dispatch_context(self) -> AbstractContextManager: ...
    def before_dispatch(self, request: AuthorizationRequest) -> str | None: ...
    def after_execution(self, request: AuthorizationRequest, output: JsonValue) -> JsonValue: ...


def _raise_if_cancelled():
    task = asyncio.current_task()
    if task is not None and task.cancelling():
        raise asyncio.CancelledError()


class ProtectedExecutor:
    def __init__(self, registry: ToolRegistry, policy: PolicyDecisionPoint,
                 audit: AuthorizationAuditSink, *, policy_version: str, policy_timeout_seconds: float = 1.0,
                 flow_guard: ExecutionFlowGuard | None = None):
        if not math.isfinite(policy_timeout_seconds) or not 0 < policy_timeout_seconds <= 60:
            raise ValueError("policy timeout must be positive, finite and at most 60 seconds")
        self._registry, self._policy, self._audit = registry, policy, audit
        self._policy_version, self._timeout = policy_version, policy_timeout_seconds
        self._flow_guard = flow_guard

    async def execute_authorized(self, invocation: ToolInvocation, trusted_context: TrustedContext | None) -> ExecutionResult:
        # Optional trusted composition. The same guard/store must cover every
        # executor serving this session; the MCP adapter cannot select or skip it.
        if self._flow_guard is None or not isinstance(trusted_context, TrustedContext):
            return await self._execute(invocation, trusted_context)
        try:
            context = TrustedContext.model_validate(trusted_context)
        except Exception:
            return await self._execute(invocation, trusted_context)
        async with self._flow_guard.session(context.principal):
            return await self._execute(invocation, context)

    async def _execute(self, invocation, trusted_context):
        _raise_if_cancelled()
        request_id, evaluation_latency_ms = uuid4(), 0.0
        principal, entry, decision = None, None, None

        def event(effect, reason, status):
            # Unknown tool identifiers are not trusted log fields.
            return AuthorizationAuditEvent(
                request_id=request_id, decision_id=decision.decision_id if decision else None,
                timestamp=datetime.now(timezone.utc), subject_id=principal.subject_id if principal else None,
                tenant_id=principal.tenant_id if principal else None,
                server_id=entry.server_id if entry else None, tool_name=entry.tool_name if entry else None,
                decision=effect, reason_code=reason, policy_version=self._policy_version,
                execution_status=status, evaluation_latency_ms=evaluation_latency_ms)

        def reject(reason, *, approval=False):
            try:
                self._audit.record(event("REQUIRE_APPROVAL" if approval else "DENY", reason, "NOT_EXECUTED"))
            except Exception:
                return ExecutionResult(request_id=request_id, status="ERROR", reason_code="AUDIT_UNAVAILABLE")
            return ExecutionResult(request_id=request_id, decision_id=decision.decision_id if decision else None,
                                   status="APPROVAL_REQUIRED" if approval else "DENIED", reason_code=reason)

        # A dict is not a trusted context, even if it contains plausible identity fields.
        if not isinstance(trusted_context, TrustedContext):
            return reject("MISSING_CONTEXT")
        try:
            context = TrustedContext.model_validate(trusted_context)
            principal = context.principal
        except Exception:
            return reject("MISSING_CONTEXT")
        try:
            proposal = ToolInvocation.model_validate(invocation)
        except Exception:
            return reject("INVALID_ARGUMENTS")
        entry = self._registry.resolve(proposal.server_id, proposal.tool_name)
        if entry is None:
            return reject("UNKNOWN_TOOL")
        try:
            # These schemas contain only immutable primitive values; no agent dict
            # survives into policy evaluation or execution.
            validated = entry.arguments_schema.model_validate(proposal.arguments)
            snapshot = canonical_json(validated.model_dump(mode="json"))
            execution_arguments = entry.arguments_schema.model_validate_json(snapshot, strict=True)
            request = AuthorizationRequest(
                request_id=request_id, principal=principal, server_id=entry.server_id, tool_name=entry.tool_name,
                arguments_json=snapshot, resource=self._registry.resource(validated.order_id),
                destination=validated.recipient if isinstance(validated, EmailArguments) else None,
                provenance_refs=context.provenance_refs)
            binding = request_digest(request)
        except Exception:
            return reject("INVALID_ARGUMENTS")
        try:
            policy_started = time.perf_counter()
            response = await asyncio.wait_for(self._policy.evaluate(request), timeout=self._timeout)
            _raise_if_cancelled()
            policy_elapsed = time.perf_counter() - policy_started
            evaluation_latency_ms = round(policy_elapsed * 1000, 3)
            # wait_for cannot force cancellation-resistant or event-loop-blocking
            # trusted evaluators to stop. A late ALLOW must still never execute.
            if policy_elapsed > self._timeout:
                return reject("POLICY_UNAVAILABLE")
        except Exception:
            evaluation_latency_ms = round((time.perf_counter() - policy_started) * 1000, 3)
            return reject("POLICY_UNAVAILABLE")
        try:
            decision = AuthorizationDecision.model_validate(response)
            if decision.request_digest != binding or decision.policy_version != self._policy_version:
                decision = None
                return reject("INVALID_DECISION")
            # An allow must use the fixed allow reason. Unknown/contradictory
            # decision encodings never become execution permissions.
            if decision.effect == "ALLOW" and decision.reason_code != "AUTHORIZED":
                decision = None
                return reject("INVALID_DECISION")
        except Exception:
            decision = None
            return reject("INVALID_DECISION")
        if decision.effect == "REQUIRE_APPROVAL":
            return reject(decision.reason_code, approval=True)
        if decision.effect != "ALLOW":
            return reject(decision.reason_code)
        try:
            self._audit.record(event("ALLOW", "AUTHORIZED", "AUTHORIZED"))
        except Exception:
            return ExecutionResult(request_id=request_id, decision_id=decision.decision_id,
                                   status="ERROR", reason_code="AUDIT_UNAVAILABLE")
        # No external grant/token is accepted. Only this invocation's private
        # validated snapshot reaches the resolved trusted callable.
        with self._flow_guard.dispatch_context() if self._flow_guard is not None else nullcontext():
            _raise_if_cancelled()
            if self._flow_guard is not None:
                try:
                    reason = self._flow_guard.before_dispatch(request)
                except Exception:
                    reason = "PROVENANCE_UNAVAILABLE"
                if reason is not None:
                    return reject(reason)
            _raise_if_cancelled()
            try:
                output = entry.executor(execution_arguments)
                if self._flow_guard is not None:
                    try:
                        output = self._flow_guard.after_execution(request, output)
                    except Exception:
                        # Retrieval may already have run, but no output is released.
                        try:
                            self._audit.record(event("ALLOW", "PROVENANCE_UNAVAILABLE", "FAILED"))
                        except Exception:
                            pass
                        return ExecutionResult(request_id=request_id, decision_id=decision.decision_id,
                                               status="ERROR", reason_code="PROVENANCE_UNAVAILABLE")
                completed = ExecutionResult(request_id=request_id, decision_id=decision.decision_id,
                                            status="EXECUTED", reason_code="AUTHORIZED", output=output)
            except Exception:
                try:
                    self._audit.record(event("ALLOW", "EXECUTION_FAILED", "FAILED"))
                except Exception:
                    pass  # Required pre-execution event already succeeded; no retry.
                return ExecutionResult(request_id=request_id, decision_id=decision.decision_id,
                                       status="ERROR", reason_code="EXECUTION_FAILED")
            try:
                self._audit.record(event("ALLOW", "AUTHORIZED", "EXECUTED"))
            except Exception:
                # A completed operation cannot be undone by failing its completion log.
                return ExecutionResult(request_id=request_id, decision_id=decision.decision_id,
                                       status="EXECUTED_AUDIT_FAILED", reason_code="AUDIT_UNAVAILABLE")
            return completed
