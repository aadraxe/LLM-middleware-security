"""Strict boundary contracts. Canonical JSON provides an immutable argument snapshot."""
import hashlib
import json
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
Effect = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
ReasonCode = Literal[
    "AUTHORIZED", "MISSING_CONTEXT", "UNKNOWN_TOOL", "INVALID_ARGUMENTS",
    "RESOURCE_NOT_FOUND", "CROSS_TENANT", "WRONG_ROLE", "DESTINATION_DENIED",
    "APPROVAL_REQUIRED", "POLICY_UNAVAILABLE", "INVALID_DECISION",
    "POLICY_NOT_CONFIGURED", "AUDIT_UNAVAILABLE", "EXECUTION_FAILED",
    "FLOW_DENIED", "PROVENANCE_UNAVAILABLE",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, revalidate_instances="always")


class TrustedPrincipal(StrictModel):
    subject_id: Identifier
    tenant_id: Identifier
    roles: frozenset[Identifier]
    session_id: Identifier


class TrustedContext(StrictModel):
    """Internal identity supplied by the application, never parsed from agent JSON."""
    principal: TrustedPrincipal
    # Reserved references only; absence stays unknown, never public/trusted.
    provenance_refs: tuple[Identifier, ...] | None = None


class ToolInvocation(StrictModel):
    """Untrusted proposal, deliberately without identity, policy or decisions."""
    server_id: Identifier
    tool_name: Identifier
    arguments: dict[str, JsonValue]


class OrderArguments(StrictModel):
    order_id: Identifier


class EmailArguments(OrderArguments):
    recipient: Annotated[str, Field(min_length=3, max_length=254,
        pattern=r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*\.[A-Za-z]{2,}$")]
    body: Annotated[str, Field(min_length=1, max_length=8192)]

    @field_validator("recipient")
    @classmethod
    def normalize_recipient(cls, value: str) -> str:
        # Synthetic support environment uses case-insensitive mailbox identities.
        return value.lower()

    @field_validator("body")
    @classmethod
    def nonblank_body(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("body must contain text")
        return value


class RefundArguments(OrderArguments):
    amount_cents: Annotated[int, Field(gt=0, le=100_000_000)]


class ResourceInfo(StrictModel):
    resource_id: Identifier
    tenant_id: Identifier


class AuthorizationRequest(StrictModel):
    request_id: UUID
    principal: TrustedPrincipal
    server_id: Identifier
    tool_name: Identifier
    # Canonical JSON, not a shared mutable dict. Full attributes reach the PDP,
    # but neither arguments nor destination are copied into audit events.
    arguments_json: str
    resource: ResourceInfo | None
    destination: str | None
    provenance_refs: tuple[Identifier, ...] | None = None

    @field_validator("arguments_json")
    @classmethod
    def canonical_arguments(cls, value: str) -> str:
        parsed = json.loads(value)
        if not isinstance(parsed, dict) or canonical_json(parsed) != value:
            raise ValueError("arguments must be a canonical JSON object")
        return value


class AuthorizationDecision(StrictModel):
    decision_id: UUID
    effect: Effect
    reason_code: ReasonCode
    policy_version: Identifier
    request_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ExecutionResult(StrictModel):
    request_id: UUID
    decision_id: UUID | None = None
    status: Literal["EXECUTED", "DENIED", "APPROVAL_REQUIRED", "ERROR", "EXECUTED_AUDIT_FAILED"]
    reason_code: ReasonCode
    output: JsonValue = None


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def request_digest(request: AuthorizationRequest) -> str:
    """Includes fresh request ID, identity/session, action, arguments and context."""
    payload = request.model_dump(mode="json")
    payload["principal"]["roles"] = sorted(request.principal.roles)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
