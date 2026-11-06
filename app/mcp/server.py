"""Official SDK protocol handlers; every supported call uses ProtectedExecutor.

Trusted harness code creates one server binding per local principal/session.
Never deploy this fixed-context factory as public HTTP authentication.
"""
import json
from types import MappingProxyType

from mcp.server import Server, ServerRequestContext
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, TextContent, Tool

from app.authorization.executor import ProtectedExecutor
from app.authorization.schemas import EmailArguments, OrderArguments, RefundArguments, ToolInvocation, TrustedContext


# Explicit protocol surface, independent of additional trusted registry entries.
_TOOLS = MappingProxyType({
    "get_order": (OrderArguments, "Fetch a synthetic order after tenant and role authorization."),
    "send_email": (EmailArguments, "Send a synthetic email only to an approved destination."),
    "issue_refund": (RefundArguments, "Issue a synthetic refund subject to role and approval limits."),
})


def _result(status: str, reason: str, *, output=None) -> CallToolResult:
    payload = {"status": status, "reason_code": reason}
    if status == "EXECUTED":
        payload["output"] = output
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, sort_keys=True))],
        structured_content=payload,
        is_error=status != "EXECUTED",
    )


def create_local_protected_server(executor: ProtectedExecutor, trusted_context: TrustedContext | None) -> Server:
    """Bind trusted local context outside all MCP parameters and request metadata.

    The host owns this binding, the executor, registry and policy. For distinct
    principals/sessions create distinct bindings; no global/contextvar identity.
    None intentionally produces fail-closed MISSING_CONTEXT on every tool call.
    """
    if trusted_context is not None and not isinstance(trusted_context, TrustedContext):
        raise TypeError("trusted context must be supplied by local harness code")
    local_context = TrustedContext.model_validate(trusted_context) if trusted_context is not None else None

    async def list_tools(_ctx: ServerRequestContext, _params: PaginatedRequestParams | None) -> ListToolsResult:
        # Fresh SDK objects so discovery consumers cannot mutate shared schemas.
        return ListToolsResult(tools=[Tool(name=name, description=description, input_schema=schema.model_json_schema())
                                     for name, (schema, description) in _TOOLS.items()])

    async def call_tool(_ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        # Never read identity from _ctx.meta, params._meta, headers, clientInfo or arguments.
        # Low-level SDK schemas are discovery only; strict runtime validation is
        # delegated to Phase 2A and must never be assumed from tools/list alone.
        if params.name not in _TOOLS:
            return _result("DENIED", "UNKNOWN_TOOL")
        try:
            proposal = ToolInvocation(server_id="support", tool_name=params.name,
                                      arguments=params.arguments if params.arguments is not None else {})
        except Exception:
            return _result("DENIED", "INVALID_ARGUMENTS")
        try:
            outcome = await executor.execute_authorized(proposal, local_context)
            return _result(outcome.status, outcome.reason_code, output=outcome.output)
        except Exception:
            # Do not expose exception text, Pydantic input values or tool bodies.
            # CancelledError remains uncaught and never triggers an unguarded retry.
            return _result("ERROR", "AUTHORIZATION_UNAVAILABLE")

    return Server("AegisFlow protected support", version="phase-2b",
                  on_list_tools=list_tools, on_call_tool=call_tool)
