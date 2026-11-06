"""Fixed public receipt, handed off before sensitive workflow execution.

No candidate, template ID, format arguments, result or outcome is accepted.
This is a precommitted acknowledgement, never conditional declassification.
"""
import inspect
from datetime import datetime, timezone
from threading import Lock
import time
from types import MappingProxyType
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from app.authorization.schemas import Identifier, StrictModel, TrustedContext
from .guard import TrustedRecipient, _cancelled, local_recipient_policy
from .session import _run_bound_agent


# Deliberately one entry: no per-result choice channel and no format slots.
_TEMPLATES = MappingProxyType({"workflow_receipt_v1": "Your request has been received."})
_WORKFLOW_SEAL = object()


class PublicAuditEvent(StrictModel):
    event_type: Literal["host_public_response_authorization"] = "host_public_response_authorization"
    content_origin: Literal["HOST_OWNED_PUBLIC"] = "HOST_OWNED_PUBLIC"
    receipt_id: UUID
    timestamp: datetime
    tenant_id: Identifier
    session_id: Identifier
    recipient_id: Identifier
    policy_version: Identifier
    decision: Literal["ALLOW"] = "ALLOW"
    reason_code: Literal["PRECOMMITTED_RECEIPT"] = "PRECOMMITTED_RECEIPT"


class InMemoryPublicAuditSink:
    def __init__(self):
        self._lock, self._events = Lock(), []

    @property
    def events(self):
        with self._lock:
            return tuple(self._events)

    def record(self, event):
        event = PublicAuditEvent.model_validate(event)
        with self._lock:
            self._events.append(event)


class HostReceipt(StrictModel):
    """Only text is public; binding/timing metadata stays host-private.

    No body construction field: even direct construction cannot label text.
    """
    receipt_id: UUID = Field(exclude=True, repr=False)
    tenant_id: Identifier = Field(exclude=True, repr=False)
    session_id: Identifier = Field(exclude=True, repr=False)
    recipient_id: Identifier = Field(exclude=True, repr=False)
    content_origin: Literal["HOST_OWNED_PUBLIC"] = "HOST_OWNED_PUBLIC"
    public_released: Literal[True] = True
    enforcement_ms: float = Field(ge=0, exclude=True, repr=False)

    @property
    def text(self):
        return _TEMPLATES["workflow_receipt_v1"]


class _ReceiptCapability:
    __slots__ = ()

    def __new__(cls):
        raise TypeError("receipt capability is issued by trusted preparation")


class PublicReceiptChannel:
    """Host-owned capability issuer; keep it and its handles away from agents.

    Preparation performs audit/release under provenance locks BEFORE planning.
    consume retrieves that already authorized value, without consulting secrets
    or waiting for tools. Its one-shot consumption is synchronized separately.
    """
    def __init__(self, store, *, policy=None, audit=None):
        self._store = store
        self._policy = local_recipient_policy() if policy is None else policy
        self._audit = InMemoryPublicAuditSink() if audit is None else audit
        self._mutex, self._ready = Lock(), {}

    async def prepare(self, context, recipient):
        started = time.perf_counter()
        _cancelled()
        try:
            if not isinstance(context, TrustedContext) or not isinstance(recipient, TrustedRecipient):
                raise ValueError()
            context = TrustedContext.model_validate(context)
            recipient = TrustedRecipient.model_validate(recipient)
            async with self._store.session(context.principal):
                with self._store.dispatch_context():
                    state = self._store.exposure(context.principal)
                    # No post-read minting, result-dependent template selection,
                    # session resets or references to private artifacts.
                    if state.revision != 0 or state.artifact_ids or context.provenance_refs:
                        raise ValueError()
                    allowed = self._policy.permits_public_receipt(context.principal, recipient)
                    if type(allowed) is not bool or not allowed:
                        raise ValueError()
                    receipt_id = uuid4()
                    acceptance = self._audit.record(PublicAuditEvent(receipt_id=receipt_id,
                        timestamp=datetime.now(timezone.utc), tenant_id=context.principal.tenant_id,
                        session_id=context.principal.session_id, recipient_id=recipient.recipient_id,
                        policy_version=self._policy.version))
                    if acceptance is not None:
                        if inspect.iscoroutine(acceptance): acceptance.close()
                        raise ValueError()
                    if self._store.exposure(context.principal) != state:
                        raise ValueError()
                    _cancelled()
                    receipt = HostReceipt(receipt_id=receipt_id, tenant_id=context.principal.tenant_id,
                        session_id=context.principal.session_id, recipient_id=recipient.recipient_id,
                        enforcement_ms=(time.perf_counter() - started) * 1000)
                    capability = object.__new__(_ReceiptCapability)
                    with self._mutex:
                        self._ready[capability] = (context, recipient, receipt)
                    return capability
        except Exception:
            raise RuntimeError("public response unavailable") from None

    def consume(self, capability, context, recipient):
        """Retrieve a precommitted handoff, never a new decision after a read."""
        try:
            if not isinstance(context, TrustedContext) or not isinstance(recipient, TrustedRecipient):
                raise ValueError()
            context = TrustedContext.model_validate(context)
            recipient = TrustedRecipient.model_validate(recipient)
            with self._mutex:
                binding = self._ready.get(capability)
                if binding is None or binding[:2] != (context, recipient):
                    raise ValueError()
                del self._ready[capability]
                return binding[2]
        except Exception:
            raise RuntimeError("public response unavailable") from None


class PublicWorkflow:
    """Already acknowledged workflow; model output still has separate egress."""
    def __init__(self, application, connection, samples, context, recipient, receipt, output_audit, *, _seal=None):
        if _seal is not _WORKFLOW_SEAL:
            raise TypeError("use audited public workflow preparation")
        if not isinstance(receipt, HostReceipt):
            raise TypeError("prepared host receipt required")
        self._application, self._connection, self._samples = application, connection, samples
        self._context, self._recipient, self._output_audit = context, recipient, output_audit
        self._receipt = HostReceipt.model_validate(receipt)
        self._used, self._run_lock = False, Lock()

    @property
    def receipt(self):
        return self._receipt

    async def run(self, planner, customer, *, limits=None, retrieval=None):
        with self._run_lock:
            if self._used:
                raise RuntimeError("public workflow already used")
            self._used = True
        try:
            return await _run_bound_agent(self._application, self._connection, self._samples, self._context,
                planner, customer, self._recipient, limits=limits, output_audit=self._output_audit, retrieval=retrieval)
        except Exception:
            raise RuntimeError("agent session unavailable") from None


async def open_public_workflow(application, actor, recipient, *, public_audit=None, output_audit=None):
    """Fixed public admission step. No planner, customer text or result input."""
    try:
        connection, samples, context = application.connect_bound(actor)
        channel = PublicReceiptChannel(application.store, audit=public_audit)
        capability = await channel.prepare(context, recipient)
        receipt = channel.consume(capability, context, recipient)
        return PublicWorkflow(application, connection, samples, context, recipient, receipt, output_audit,
                              _seal=_WORKFLOW_SEAL)
    except Exception:
        raise RuntimeError("public response unavailable") from None
