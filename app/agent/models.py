"""Trusted scenario definitions, separate from proposed tool arguments."""
import json
from typing import Literal

from pydantic import field_validator, model_validator
from app.authorization.schemas import Identifier, StrictModel, canonical_json


class Step(StrictModel):
    id: Identifier
    tool: Literal["get_order", "send_email", "issue_refund"]
    arguments_json: str
    ground_truth: Literal["legitimate", "prohibited"] = "legitimate"
    depends_on: Identifier | None = None
    copy_order_from: Identifier | None = None
    on_failure: Literal["stop", "continue"] = "stop"

    @field_validator("arguments_json")
    @classmethod
    def arguments_object(cls, value):
        parsed = json.loads(value)
        if not isinstance(parsed, dict) or canonical_json(parsed) != value:
            raise ValueError("canonical argument object required")
        return value

    @model_validator(mode="after")
    def explicit_dependency(self):
        if self.copy_order_from is not None and (self.tool != "send_email" or self.copy_order_from != self.depends_on):
            raise ValueError("copy requires an explicit email dependency")
        return self


class Plan(StrictModel):
    steps: tuple[Step, ...]

    @model_validator(mode="after")
    def ordered_dependencies(self):
        seen = {}
        for step in self.steps:
            if step.id in seen or (step.depends_on is not None and step.depends_on not in seen):
                raise ValueError("unique ordered dependencies required")
            if step.copy_order_from and seen[step.copy_order_from].tool != "get_order":
                raise ValueError("copy source must be an order retrieval")
            seen[step.id] = step
        if not seen:
            raise ValueError("plan must contain steps")
        return self


class Actor(StrictModel):
    """Host-only fixture profile; never accepted by a tool or agent payload."""
    id: Identifier
    tenant_id: Identifier = "tenant-a"
    roles: frozenset[Identifier] = frozenset({"support_read", "support_email", "support_refund"})
    exposure: Literal["clean", "unknown", "missing"] = "clean"
    plan: Plan


class Scenario(StrictModel):
    id: Identifier
    objective: str
    legitimate_task: bool
    actors: tuple[Actor, ...]
    # Expected execution completion, not an input to enforcement or scoring.
    expected_completion: tuple[bool, bool, bool]  # authorization / provenance / unsafe
    # Same configurations; each triple counts get_order / send_email / issue_refund.
    expected_tool_executions: tuple[tuple[int, int, int], tuple[int, int, int], tuple[int, int, int]]

    @model_validator(mode="after")
    def unique_actors(self):
        if not self.actors or len({a.id for a in self.actors}) != len(self.actors):
            raise ValueError("unique actors required")
        return self
