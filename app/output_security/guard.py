"""Conservative local egress handoff under the shared provenance locks.

Only trusted host code supplies context, recipient, policy, store and sink.
The candidate's wording never supplies labels, identity or disclosure authority.
"""
import asyncio
import inspect
from datetime import datetime, timezone
from threading import Lock
import time
from types import MappingProxyType
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field
from app.authorization.schemas import Identifier, StrictModel, TrustedContext
from app.provenance.models import Sensitivity

SAFE_RESPONSE = "I cannot release this response under the current disclosure policy."
Effect = Literal["ALLOW", "DENY", "UNRESOLVED"]
Reason = Literal["OUTPUT_ALLOWED", "RECIPIENT_DENIED", "MISSING_RECIPIENT", "INVALID_CONTEXT",
                 "PROVENANCE_UNAVAILABLE", "OUTPUT_LIMIT", "NO_FINAL", "OUTPUT_AUDIT_UNAVAILABLE",
                 "OUTPUT_STATE_CHANGED"]


def _cancelled():
    task = asyncio.current_task()
    if task is not None and task.cancelling():
        raise asyncio.CancelledError()


class TrustedRecipient(StrictModel):
    """Local fixture identity, never constructed from a customer/model payload."""
    recipient_id: Identifier
    tenant_id: Identifier


class OutputDecision(StrictModel):
    request_id: UUID
    effect: Effect
    reason_code: Reason
    sensitivity: Sensitivity
    policy_version: Identifier


class ReleasedResponse(StrictModel):
    decision: OutputDecision
    model_text_released: bool
    enforcement_ms: float = Field(ge=0)
    # Text is for the trusted outward handoff, never default report/repr output.
    text: str = Field(exclude=True, repr=False)


class OutputAuditEvent(StrictModel):
    event_type: Literal["final_response_authorization"] = "final_response_authorization"
    request_id: UUID
    timestamp: datetime
    tenant_id: Identifier | None
    subject_id: Identifier | None
    session_id: Identifier | None
    recipient_id: Identifier | None
    sensitivity: Sensitivity
    exposure_revision: int | None = Field(ge=0)
    effect: Effect
    reason_code: Reason
    policy_version: Identifier


class InMemoryOutputAuditSink:
    def __init__(self):
        self._lock, self._events = Lock(), []

    @property
    def events(self):
        with self._lock:
            return tuple(self._events)

    def record(self, event):
        event = OutputAuditEvent.model_validate(event)
        with self._lock:
            self._events.append(event)


class RecipientPolicy:
    def __init__(self, grants, *, version="output-v1"):
        # Snapshot only explicit host grants. No role/initiator inheritance.
        self.version = IdentifierModel(value=version).value
        snapshot = {}
        for (tenant, recipient), levels in grants.items():
            identity = TrustedRecipient(tenant_id=tenant, recipient_id=recipient)
            snapshot[(identity.tenant_id, identity.recipient_id)] = frozenset(Sensitivity(s) for s in levels)
        self._grants = MappingProxyType(snapshot)

    def permits(self, principal, recipient, exposure):
        return (recipient.tenant_id == principal.tenant_id and exposure.sensitivity != Sensitivity.UNKNOWN
                and exposure.sensitivity in self._grants.get((recipient.tenant_id, recipient.recipient_id), frozenset()))

    def permits_public_receipt(self, principal, recipient):
        """Identity-only permission for fixed host content, never model text."""
        return (recipient.tenant_id == principal.tenant_id and Sensitivity.PUBLIC in
                self._grants.get((recipient.tenant_id, recipient.recipient_id), frozenset()))


class IdentifierModel(StrictModel):
    value: Identifier


def local_recipient_policy():
    """Public-only local recipient fixtures; confidential access is never default."""
    return RecipientPolicy({(tenant, "public-viewer"): {Sensitivity.PUBLIC, Sensitivity.INTERNAL}
                            for tenant in ("tenant-a", "tenant-b")})


class FinalResponseGuard:
    def __init__(self, store, policy: RecipientPolicy, audit):
        if not isinstance(policy, RecipientPolicy):
            raise TypeError("trusted recipient policy required")
        self._store, self._policy, self._audit = store, policy, audit

    async def release(self, candidate, context, recipient):
        """Commit one immutable local handoff; no await in check/audit/handoff.

        Session serialization is shared with ProtectedExecutor. The store mutex
        excludes cross-thread updates until the released value is constructed.
        Later exposure cannot retroactively revoke an already handed-off value.
        """
        started, request_id = time.perf_counter(), uuid4()
        trusted, target, state = None, None, None

        def commit(effect, reason):
            sensitivity = state.sensitivity if state is not None else Sensitivity.UNKNOWN
            return ReleasedResponse(decision=OutputDecision(request_id=request_id, effect=effect,
                reason_code=reason, sensitivity=sensitivity, policy_version=self._policy.version),
                model_text_released=effect == "ALLOW", text=candidate if effect == "ALLOW" else SAFE_RESPONSE,
                enforcement_ms=(time.perf_counter() - started) * 1000)

        def audit(effect, reason):
            acceptance = self._audit.record(OutputAuditEvent(request_id=request_id, timestamp=datetime.now(timezone.utc),
                tenant_id=trusted.principal.tenant_id if trusted else None,
                subject_id=trusted.principal.subject_id if trusted else None,
                session_id=trusted.principal.session_id if trusted else None,
                recipient_id=target.recipient_id if target else None,
                sensitivity=state.sensitivity if state else Sensitivity.UNKNOWN,
                exposure_revision=state.revision if state else None, effect=effect, reason_code=reason,
                policy_version=self._policy.version))
            if acceptance is not None:
                # This boundary requires a synchronous, raising-on-failure sink.
                # An unawaited async sink has not accepted the required event.
                if inspect.iscoroutine(acceptance):
                    acceptance.close()
                raise ValueError("invalid output audit acceptance")

        def reject(effect, reason):
            try:
                audit(effect, reason)
            except Exception:
                return commit("UNRESOLVED", "OUTPUT_AUDIT_UNAVAILABLE")
            _cancelled()
            return commit(effect, reason)

        _cancelled()
        try:
            if not isinstance(context, TrustedContext):
                raise ValueError()
            trusted = TrustedContext.model_validate(context)
        except Exception:
            return reject("UNRESOLVED", "INVALID_CONTEXT")
        try:
            if not isinstance(recipient, TrustedRecipient):
                raise ValueError()
            target = TrustedRecipient.model_validate(recipient)
        except Exception:
            return reject("UNRESOLVED", "MISSING_RECIPIENT")
        try:
            async with self._store.session(trusted.principal):
                with self._store.dispatch_context():
                    _cancelled()
                    state = self._store.exposure(trusted.principal)
                    # Reserved references cannot weaken or bypass session exposure.
                    for reference in trusted.provenance_refs or ():
                        self._store.lineage(UUID(reference), trusted.principal)
                    if candidate is None:
                        return reject("UNRESOLVED", "NO_FINAL")
                    if type(candidate) is not str or not candidate or len(candidate) > 8192 or len(candidate.encode()) > 16384:
                        return reject("UNRESOLVED", "OUTPUT_LIMIT")
                    if state.sensitivity == Sensitivity.UNKNOWN:
                        return reject("UNRESOLVED", "PROVENANCE_UNAVAILABLE")
                    allowed = self._policy.permits(trusted.principal, target, state)
                    if type(allowed) is not bool:
                        raise ValueError()
                    if not allowed:
                        return reject("DENY", "RECIPIENT_DENIED")
                    try:
                        audit("ALLOW", "OUTPUT_ALLOWED")
                    except Exception:
                        return commit("UNRESOLVED", "OUTPUT_AUDIT_UNAVAILABLE")
                    # A synchronous trusted audit callback can reenter the store.
                    if self._store.exposure(trusted.principal) != state:
                        return reject("UNRESOLVED", "OUTPUT_STATE_CHANGED")
                    _cancelled()
                    return commit("ALLOW", "OUTPUT_ALLOWED")
        except Exception:
            return reject("UNRESOLVED", "PROVENANCE_UNAVAILABLE")
