"""Actual SDK client/server interactions over native memory JSON-RPC transport."""
import asyncio
import json
from uuid import uuid4

import pytest
from mcp import Client
from mcp.types import RequestParamsMeta

from app.authorization.audit import InMemoryAuditSink
from app.authorization.executor import ProtectedExecutor
from app.authorization.fakes import FakeSupportEnvironment
from app.authorization.policy import InMemoryPolicy, PolicyConfig
from app.authorization.registry import RegisteredTool, ToolAttributes, ToolRegistry
from app.authorization.schemas import OrderArguments, ToolInvocation, TrustedContext, TrustedPrincipal
from app.mcp.server import create_local_protected_server


ROLES = frozenset({"support_read", "support_email", "support_refund"})


def context(roles=ROLES, *, tenant="tenant-a", subject="user-a", session="session-a"):
    return TrustedContext(principal=TrustedPrincipal(subject_id=subject, tenant_id=tenant,
                          roles=roles, session_id=session))


def build(trusted, *, policy_factory=None, sink=None):
    env = FakeSupportEnvironment()
    registry = env.registry()
    config = PolicyConfig(version="v1", refund_approval_threshold_cents=5000,
                          approved_destinations=frozenset({("tenant-a", "support@example.test")}))
    policy = InMemoryPolicy(registry, config)
    if policy_factory:
        policy = policy_factory(policy)
    audit = InMemoryAuditSink() if sink is None else sink
    boundary = ProtectedExecutor(registry, policy, audit, policy_version="v1", policy_timeout_seconds=.1)
    return env, audit, boundary, create_local_protected_server(boundary, trusted)


async def call(server, name="get_order", arguments=None, *, meta=None):
    # legacy intentionally exercises initialize/initialized and SDK JSON-RPC
    # streams. Default auto mode instead uses the SDK's direct modern dispatcher.
    async with Client(server, mode="legacy", cache=None) as client:
        assert client.session.initialize_result is not None
        return await client.call_tool(name, arguments if arguments is not None else {"order_id": "order-a"}, meta=meta)


def payload(result):
    assert len(result.content) == 1
    data = json.loads(result.content[0].text)
    assert data == result.structured_content
    return data


def test_initialization_and_exact_discovery():
    env, _, _, server = build(context())
    async def scenario():
        async with Client(server, mode="legacy", cache=None) as client:
            assert client.session.initialize_result is not None
            assert client.protocol_version == client.session.initialize_result.protocol_version
            assert client.server_info.name == "AegisFlow protected support"
            assert client.server_capabilities.tools is not None
            assert client.server_capabilities.resources is None
            assert client.server_capabilities.prompts is None
            tools = (await client.list_tools()).tools
            assert {t.name for t in tools} == {"get_order", "send_email", "issue_refund"}
            assert len(tools) == 3
            for tool in tools:
                assert tool.input_schema["additionalProperties"] is False
                assert not {"principal", "roles", "tenant_id", "subject_id", "policy", "decision"}.intersection(tool.input_schema["properties"])
    asyncio.run(scenario())
    assert not env.calls


@pytest.mark.parametrize("tool,args", [
    ("get_order", {"order_id": "order-a"}),
    ("send_email", {"order_id": "order-a", "recipient": "SUPPORT@example.test", "body": "synthetic message"}),
    ("issue_refund", {"order_id": "order-a", "amount_cents": 5000}),
])
def test_authorized_protocol_call_executes_once(tool, args):
    env, audit, _, server = build(context())
    result = asyncio.run(call(server, tool, args))
    assert result.is_error is False and payload(result)["status"] == "EXECUTED"
    assert env.calls[tool] == 1 and sum(env.calls.values()) == 1
    assert [e.execution_status for e in audit.events] == ["AUTHORIZED", "EXECUTED"]
    if tool == "send_email": assert env.arguments[0][1]["recipient"] == "support@example.test"


@pytest.mark.parametrize("tool,args,trusted,reason", [
    ("get_order", {"order_id": "order-a"}, context(roles=frozenset()), "WRONG_ROLE"),
    ("get_order", {"order_id": "order-b"}, context(), "CROSS_TENANT"),
    ("send_email", {"order_id": "order-a", "recipient": "outside@example.test", "body": "hello"}, context(), "DESTINATION_DENIED"),
    ("issue_refund", {"order_id": "order-a", "amount_cents": 5001}, context(), "APPROVAL_REQUIRED"),
    ("get_order", {"order_id": "order-a"}, None, "MISSING_CONTEXT"),
    ("get_order", {"order_id": "order-missing"}, context(), "RESOURCE_NOT_FOUND"),
])
def test_protocol_denials_execute_zero(tool, args, trusted, reason):
    env, _, _, server = build(trusted)
    result = asyncio.run(call(server, tool, args))
    assert result.is_error is True and payload(result)["reason_code"] == reason
    assert not env.calls and env.arguments == []
    assert "output" not in payload(result)


@pytest.mark.parametrize("tool", ["get_customer_record", "search_knowledge_base", "exec", "GET_ORDER", "support/get_order", "get_order "])
def test_unknown_or_alias_tools_cannot_execute(tool):
    env, _, _, server = build(context())
    result = asyncio.run(call(server, tool))
    assert result.is_error is True and payload(result)["reason_code"] == "UNKNOWN_TOOL"
    assert not env.calls


@pytest.mark.parametrize("tool,args", [
    ("get_order", {}), ("get_order", {"order_id": 123}),
    ("get_order", {"order_id": "order-a", "unexpected": "synthetic-secret"}),
    ("send_email", {"order_id": "order-a", "recipient": "support@example.test"}),
    ("send_email", {"order_id": "order-a", "recipient": "bad-address", "body": "secret"}),
    ("issue_refund", {"order_id": "order-a", "amount_cents": True}),
    ("issue_refund", {"order_id": "order-a", "amount_cents": "100"}),
    ("issue_refund", {"order_id": "order-a", "amount_cents": -1}),
    ("issue_refund", {"order_id": "order-a", "amount_cents": 1.5}),
])
def test_invalid_arguments_never_reach_underlying_tool(tool, args):
    env, _, _, server = build(context())
    result = asyncio.run(call(server, tool, args))
    assert result.is_error is True and payload(result)["reason_code"] == "INVALID_ARGUMENTS"
    assert not env.calls


@pytest.mark.parametrize("key,value", [
    ("subject_id", "admin"), ("tenant_id", "tenant-b"), ("roles", ["support_refund"]),
    ("principal", {"subject_id": "admin"}), ("session_id", "admin"),
    ("policy", {"allow": True}), ("decision", {"effect": "ALLOW"}),
    ("provenance_refs", ["public"]), ("classifier_verdict", "allow"), ("server_id", "admin"),
])
def test_forged_authority_arguments_do_not_elevate(key, value):
    env, _, _, server = build(context(roles=frozenset()))
    result = asyncio.run(call(server, arguments={"order_id": "order-a", key: value}))
    assert result.is_error is True and payload(result)["reason_code"] == "INVALID_ARGUMENTS"
    assert not env.calls


def test_client_metadata_cannot_set_identity():
    env, _, _, server = build(context(roles=frozenset()))
    meta: RequestParamsMeta = {"roles": ["support_read"], "principal": {"tenant_id": "tenant-a"}}
    result = asyncio.run(call(server, meta=meta))
    assert result.is_error is True and payload(result)["reason_code"] == "WRONG_ROLE"
    assert not env.calls


@pytest.mark.parametrize("mode", ["timeout", "exception", "none", "replay"])
def test_policy_failures_are_closed_over_mcp(mode):
    class BadPolicy:
        async def evaluate(self, request):
            if mode == "timeout": await asyncio.sleep(10)
            if mode == "exception": raise RuntimeError("synthetic-sensitive-provider-error")
            if mode == "none": return None
            from app.authorization.schemas import AuthorizationDecision
            return AuthorizationDecision(decision_id=uuid4(), effect="ALLOW", reason_code="AUTHORIZED",
                                         policy_version="v1", request_digest="0" * 64)
    env, _, _, server = build(context(), policy_factory=lambda _: BadPolicy())
    result = asyncio.run(call(server))
    assert result.is_error is True and payload(result)["status"] == "DENIED"
    assert not env.calls


def test_mcp_errors_and_logs_do_not_expose_sensitive_arguments(caplog, capsys):
    import logging
    caplog.set_level(logging.DEBUG)
    secret = "synthetic-email-financial-secret-819"
    env, audit, _, server = build(context())
    result = asyncio.run(call(server, "send_email", {"order_id": "order-a", "recipient": "outside@example.test", "body": secret}))
    assert result.is_error and not env.calls
    text = result.model_dump_json() + caplog.text + "".join(e.model_dump_json() for e in audit.events)
    captured = capsys.readouterr()
    assert secret not in text + captured.out + captured.err
    assert "outside@example.test" not in result.model_dump_json()


def test_unexpected_boundary_exception_is_sanitized(monkeypatch, caplog, capsys):
    env, _, boundary, server = build(context())
    async def fail(*args): raise RuntimeError("synthetic-private-boundary-secret")
    monkeypatch.setattr(boundary, "execute_authorized", fail)
    result = asyncio.run(call(server))
    captured = capsys.readouterr()
    assert payload(result) == {"status": "ERROR", "reason_code": "AUTHORIZATION_UNAVAILABLE"}
    assert "synthetic-private" not in result.model_dump_json() + caplog.text + captured.out + captured.err
    assert not env.calls


def test_required_audit_failure_blocks_mcp_tool():
    class FailedAudit:
        def record(self, event): raise OSError("synthetic-audit-secret")
    env, _, _, server = build(context(), sink=FailedAudit())
    result = asyncio.run(call(server))
    assert result.is_error and payload(result)["reason_code"] == "AUDIT_UNAVAILABLE"
    assert not env.calls


def test_concurrent_sessions_cannot_share_or_override_context():
    env, audit, boundary, server_a = build(context())
    server_b = create_local_protected_server(boundary, context(tenant="tenant-b", subject="user-b", session="session-b"))
    async def scenario():
        async with Client(server_a, mode="legacy", cache=None) as a, Client(server_b, mode="legacy", cache=None) as b:
            results = await asyncio.gather(
                a.call_tool("get_order", {"order_id": "order-a"}),
                b.call_tool("get_order", {"order_id": "order-b"}),
                a.call_tool("get_order", {"order_id": "order-b"}),
                b.call_tool("get_order", {"order_id": "order-a"}),
            )
            assert [r.is_error for r in results] == [False, False, True, True]
    asyncio.run(scenario())
    assert env.calls["get_order"] == 2
    events = [e for e in audit.events if e.execution_status == "EXECUTED"]
    assert {(e.subject_id, e.tenant_id) for e in events} == {("user-a", "tenant-a"), ("user-b", "tenant-b")}


def test_adapter_does_not_expose_extra_trusted_registry_tools():
    env = FakeSupportEnvironment()
    original = env.registry()
    extra = RegisteredTool("support", "hidden_tool", OrderArguments, env.get_order,
                           ToolAttributes(required_role="support_read", operation="read"))
    tools = [original.resolve("support", n) for n in ("get_order", "send_email", "issue_refund")]
    registry = ToolRegistry([*tools, extra], tuple(original._resources.values()))
    boundary = ProtectedExecutor(registry, InMemoryPolicy(registry, PolicyConfig(version="v1", refund_approval_threshold_cents=5000)),
                                 InMemoryAuditSink(), policy_version="v1")
    server = create_local_protected_server(boundary, context())
    result = asyncio.run(call(server, "hidden_tool"))
    assert result.is_error and payload(result)["reason_code"] == "UNKNOWN_TOOL"
    assert not env.calls


def test_raw_agent_dict_cannot_configure_trusted_server_identity():
    _, _, boundary, _ = build(context())
    with pytest.raises(TypeError): create_local_protected_server(boundary, {"principal": {"roles": ["admin"]}})


def test_repeated_calls_each_require_a_new_authorization():
    env, audit, _, server = build(context())
    async def scenario():
        async with Client(server, mode="legacy", cache=None) as client:
            for _ in range(2):
                assert not (await client.call_tool("get_order", {"order_id": "order-a"})).is_error
    asyncio.run(scenario())
    assert env.calls["get_order"] == 2
    approved = [e for e in audit.events if e.execution_status == "AUTHORIZED"]
    assert len(approved) == 2 and len({e.request_id for e in approved}) == 2
    assert len({e.decision_id for e in approved}) == 2


def test_modern_in_process_sdk_path_cannot_bypass_authorization():
    env, _, boundary, denied_server = build(context(roles=frozenset()))
    allowed_server = create_local_protected_server(boundary, context())
    async def scenario():
        async with Client(denied_server, cache=None) as denied:
            assert {t.name for t in (await denied.list_tools()).tools} == {"get_order", "send_email", "issue_refund"}
            result = await denied.call_tool("get_order", {"order_id": "order-a"})
            assert result.is_error and payload(result)["reason_code"] == "WRONG_ROLE"
            assert not env.calls
        async with Client(allowed_server, cache=None) as allowed:
            assert not (await allowed.call_tool("get_order", {"order_id": "order-a"})).is_error
    asyncio.run(scenario())
    assert env.calls["get_order"] == 1


def test_client_cancellation_does_not_execute_tool():
    started = None
    class WaitingPolicy:
        async def evaluate(self, request):
            started.set()
            await asyncio.sleep(10)
    env, _, _, server = build(context(), policy_factory=lambda _: WaitingPolicy())
    async def scenario():
        nonlocal started
        started = asyncio.Event()
        async with Client(server, mode="legacy", cache=None) as client:
            task = asyncio.create_task(client.call_tool("get_order", {"order_id": "order-a"}))
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(scenario())
    assert not env.calls
