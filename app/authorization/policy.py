"""Deterministic, trusted in-memory rules; no classifier or external service."""
import json
from typing import Annotated, Protocol
from uuid import uuid4

from pydantic import Field, field_validator

from .registry import ToolRegistry
from .schemas import (AuthorizationDecision, AuthorizationRequest, Identifier,
                      StrictModel, request_digest)


class PolicyDecisionPoint(Protocol):
    async def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        ...


class PolicyConfig(StrictModel):
    version: Identifier
    refund_approval_threshold_cents: Annotated[int, Field(ge=0)]
    # Trusted per-tenant allowlist; exact synthetic mailbox addresses, not domains.
    approved_destinations: frozenset[tuple[Identifier, str]] = frozenset()

    @field_validator("approved_destinations")
    @classmethod
    def canonical_destinations(cls, values):
        return frozenset((tenant, destination.lower()) for tenant, destination in values)


class InMemoryPolicy:
    def __init__(self, registry: ToolRegistry, config: PolicyConfig | None):
        self._registry = registry
        self._config = PolicyConfig.model_validate(config) if config is not None else None

    async def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        effect, reason = "DENY", "POLICY_NOT_CONFIGURED"
        version = self._config.version if self._config else "unconfigured"
        if self._config is not None:
            entry = self._registry.resolve(request.server_id, request.tool_name)
            if entry is None:
                reason = "UNKNOWN_TOOL"
            elif request.resource is None:
                reason = "RESOURCE_NOT_FOUND"
            elif request.resource.tenant_id != request.principal.tenant_id:
                reason = "CROSS_TENANT"
            elif entry.attributes.required_role not in request.principal.roles:
                reason = "WRONG_ROLE"
            elif request.tool_name == "send_email" and (
                    request.principal.tenant_id, request.destination) not in self._config.approved_destinations:
                reason = "DESTINATION_DENIED"
            elif request.tool_name == "issue_refund" and json.loads(request.arguments_json)["amount_cents"] > self._config.refund_approval_threshold_cents:
                effect, reason = "REQUIRE_APPROVAL", "APPROVAL_REQUIRED"
            else:
                effect, reason = "ALLOW", "AUTHORIZED"
        return AuthorizationDecision(decision_id=uuid4(), effect=effect, reason_code=reason,
                                     policy_version=version, request_digest=request_digest(request))
