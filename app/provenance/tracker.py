"""Trusted executor extension: session serialization, flow checks and labeling."""
from datetime import datetime, timezone
from typing import Literal, Protocol
from threading import Lock
import math
import time
from uuid import UUID

from app.authorization.schemas import Identifier, StrictModel
from .models import Exposure, Sensitivity


class FlowAuditEvent(StrictModel):
    event_type: Literal["information_flow"] = "information_flow"
    request_id: UUID
    timestamp: datetime
    server_id: Identifier
    tool_name: Identifier
    tenant_id: Identifier
    session_id: Identifier
    artifact_ids: tuple[UUID, ...]
    sensitivity: Sensitivity
    decision: Literal["ALLOW", "DENY"]
    reason_code: Literal["FLOW_ALLOWED", "FLOW_DENIED", "PROVENANCE_UNAVAILABLE", "EXPOSURE_RECORDED"]
    policy_version: Identifier
    execution_status: Literal["AUTHORIZED", "NOT_EXECUTED", "EXPOSURE_RECORDED"]


class FlowAuditSink(Protocol):
    def record(self, event: FlowAuditEvent) -> None: ...


class InMemoryFlowAuditSink:
    """Synchronized local fixture, not a durable audit service."""
    def __init__(self):
        self._lock, self._events = Lock(), []

    @property
    def events(self):
        with self._lock:
            return tuple(self._events)

    def record(self, event):
        validated = FlowAuditEvent.model_validate(event)
        with self._lock:
            self._events.append(validated)


class ProvenanceGuard:
    def __init__(self, store, policy, audit: FlowAuditSink, *, policy_timeout_seconds=1.0):
        if not math.isfinite(policy_timeout_seconds) or not 0 < policy_timeout_seconds <= 60:
            raise ValueError("invalid flow policy timeout")
        self._store, self._policy, self._audit = store, policy, audit
        self._timeout = policy_timeout_seconds

    def session(self, principal):
        return self._store.session(principal)

    def dispatch_context(self):
        return self._store.dispatch_context()

    def _event(self, request, state, *, decision, reason, status, artifact_ids=None):
        self._audit.record(FlowAuditEvent(request_id=request.request_id, timestamp=datetime.now(timezone.utc),
            server_id=request.server_id, tool_name=request.tool_name, tenant_id=request.principal.tenant_id,
            session_id=request.principal.session_id, artifact_ids=state.artifact_ids if artifact_ids is None else artifact_ids,
            sensitivity=state.sensitivity, decision=decision, reason_code=reason,
            policy_version=self._policy.version, execution_status=status))

    def before_dispatch(self, request):
        if (request.server_id, request.tool_name) != ("support", "send_email"):
            return None
        try:
            state = self._store.exposure(request.principal)
            # Optional trusted references must resolve in this exact session.
            for reference in request.provenance_refs or ():
                self._store.lineage(UUID(reference), request.principal)
            started = time.perf_counter()
            permitted = self._policy.permits(request, state)
            if type(permitted) is not bool or time.perf_counter() - started > self._timeout:
                raise ValueError("undefined flow decision")
            self._event(request, state, decision="ALLOW" if permitted else "DENY",
                reason="FLOW_ALLOWED" if permitted else "FLOW_DENIED",
                status="AUTHORIZED" if permitted else "NOT_EXECUTED")
            # Audit callbacks are trusted but may synchronously change exposure.
            # Recheck the exact snapshot after all pre-dispatch callbacks.
            if self._store.exposure(request.principal) != state:
                raise ValueError("exposure changed before dispatch")
            return None if permitted else "FLOW_DENIED"
        except Exception:
            try:
                unknown = Exposure(tenant_id=request.principal.tenant_id, session_id=request.principal.session_id,
                    subject_id=request.principal.subject_id, sensitivity=Sensitivity.UNKNOWN, revision=0)
                self._event(request, unknown, decision="DENY", reason="PROVENANCE_UNAVAILABLE", status="NOT_EXECUTED")
            except Exception:
                pass
            return "PROVENANCE_UNAVAILABLE"

    def after_execution(self, request, output):
        if (request.server_id, request.tool_name) != ("support", "get_order"):
            return output
        try:
            artifact = self._store.record_order(request.principal, request.resource, output)
            state = self._store.exposure(request.principal)
            self._event(request, state, decision="ALLOW", reason="EXPOSURE_RECORDED", status="EXPOSURE_RECORDED")
            return {"data": output, "artifact_id": str(artifact.artifact_id)}
        except Exception:
            # Never reset to clean after uncertain tracking/audit completion.
            self._store.poison(request.principal)
            raise
