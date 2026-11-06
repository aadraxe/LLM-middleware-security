"""Registry construction is a trusted composition step, not an agent operation."""
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Iterable

from pydantic import JsonValue

from .schemas import (EmailArguments, Identifier, OrderArguments, RefundArguments,
                      ResourceInfo, StrictModel)


class ToolAttributes(StrictModel):
    required_role: Identifier
    operation: str


@dataclass(frozen=True)
class RegisteredTool:
    server_id: str
    tool_name: str
    arguments_schema: type[OrderArguments]
    executor: Callable[[OrderArguments], JsonValue]
    attributes: ToolAttributes


class ToolRegistry:
    def __init__(self, tools: Iterable[RegisteredTool], resources: Iterable[ResourceInfo]):
        table = {}
        for tool in tools:
            key = (tool.server_id, tool.tool_name)
            if key in table:
                raise ValueError("duplicate tool registration")
            table[key] = tool
        catalogue = {}
        for resource in resources:
            validated = ResourceInfo.model_validate(resource)
            if validated.resource_id in catalogue:
                raise ValueError("ambiguous resource registration")
            catalogue[validated.resource_id] = validated
        self._tools = MappingProxyType(table)
        self._resources = MappingProxyType(catalogue)

    def resolve(self, server_id: str, tool_name: str) -> RegisteredTool | None:
        return self._tools.get((server_id, tool_name))

    def resource(self, order_id: str) -> ResourceInfo | None:
        return self._resources.get(order_id)


def support_registry(*, get_order: Callable, send_email: Callable, issue_refund: Callable,
                     resources: Iterable[ResourceInfo]) -> ToolRegistry:
    """Explicit trusted references; no imports, eval or getattr from agent strings."""
    return ToolRegistry((
        RegisteredTool("support", "get_order", OrderArguments, get_order,
                       ToolAttributes(required_role="support_read", operation="read")),
        RegisteredTool("support", "send_email", EmailArguments, send_email,
                       ToolAttributes(required_role="support_email", operation="send")),
        RegisteredTool("support", "issue_refund", RefundArguments, issue_refund,
                       ToolAttributes(required_role="support_refund", operation="refund")),
    ), resources)
