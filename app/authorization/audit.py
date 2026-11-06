"""Separate authorization events. No screening verdicts, raw arguments or digests."""
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from .schemas import Effect, Identifier, ReasonCode, StrictModel


class AuthorizationAuditEvent(StrictModel):
    event_type: Literal["tool_authorization"] = "tool_authorization"
    request_id: UUID
    decision_id: UUID | None
    timestamp: datetime
    subject_id: Identifier | None
    tenant_id: Identifier | None
    server_id: Identifier | None
    tool_name: Identifier | None
    decision: Effect
    reason_code: ReasonCode
    policy_version: Identifier
    execution_status: Literal["NOT_EXECUTED", "AUTHORIZED", "EXECUTED", "FAILED"]
    evaluation_latency_ms: float


class AuthorizationAuditSink(Protocol):
    def record(self, event: AuthorizationAuditEvent) -> None:
        """Return only after accepting the required event, or raise."""
        ...


class InMemoryAuditSink:
    """Local test sink; not durable, distributed or a production audit service."""
    def __init__(self):
        self._events: list[AuthorizationAuditEvent] = []

    @property
    def events(self) -> tuple[AuthorizationAuditEvent, ...]:
        return tuple(self._events)

    def record(self, event: AuthorizationAuditEvent) -> None:
        self._events.append(AuthorizationAuditEvent.model_validate(event))
