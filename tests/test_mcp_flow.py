"""Native MCP experiment: invocation permission does not authorize egress."""
import asyncio
from uuid import uuid4

import pytest
from mcp import Client

from app.authorization.audit import InMemoryAuditSink
from app.authorization.executor import ProtectedExecutor
from app.authorization.fakes import FakeSupportEnvironment
from app.authorization.policy import InMemoryPolicy, PolicyConfig
from app.authorization.schemas import ToolInvocation, request_digest
from app.mcp.server import create_local_protected_server
from app.provenance.flow_policy import FlowPolicy
from app.provenance.models import Sensitivity
from app.provenance.store import ArtifactStore
from app.provenance.tracker import InMemoryFlowAuditSink, ProvenanceGuard
from test_mcp import context, call, payload

EMAIL = {"order_id": "order-a", "recipient": "support@example.test", "body": "harmless synthetic greeting"}


def build(*, clean=True, register=True, policy_factory=None, auth_audit=None, flow_audit=None, allowed=None):
    env, store = FakeSupportEnvironment(), ArtifactStore()
    trusted = context()
    if register: store.register_session(trusted.principal, known_clean=clean)
    registry = env.registry()
    policy = InMemoryPolicy(registry, PolicyConfig(version="v1", refund_approval_threshold_cents=5000,
        approved_destinations=frozenset({("tenant-a", EMAIL["recipient"])})))
    if policy_factory: policy = policy_factory(policy)
    audit = InMemoryAuditSink() if auth_audit is None else auth_audit
    flow_audit = InMemoryFlowAuditSink() if flow_audit is None else flow_audit
    flow = FlowPolicy({("tenant-a", EMAIL["recipient"]): allowed or {Sensitivity.PUBLIC, Sensitivity.INTERNAL}})
    guard = ProvenanceGuard(store, flow, flow_audit)
    boundary = ProtectedExecutor(registry, policy, audit, policy_version="v1", policy_timeout_seconds=.1, flow_guard=guard)
    return env, store, trusted, boundary, create_local_protected_server(boundary, trusted), audit, flow_audit


def test_scenarios_a_b_c_d_and_false_positive_measurement():
    env, store, trusted, boundary, server, audit, flow_audit = build()
    async def scenario():
        async with Client(server, mode="legacy", cache=None) as client:
            assert not (await client.call_tool("send_email", EMAIL)).is_error  # A
            assert env.calls["send_email"] == 1
            denied = await client.call_tool("send_email", {**EMAIL, "recipient": "outside@example.test"})
            assert payload(denied)["reason_code"] == "DESTINATION_DENIED"  # B
            assert env.calls["send_email"] == 1
            result = await client.call_tool("get_order", {"order_id": "order-a"})
            reference = payload(result)["output"]["artifact_id"]
            from uuid import UUID
            artifact = store.resolve(UUID(reference), trusted.principal)
            assert artifact.sensitivity == Sensitivity.CONFIDENTIAL
            # Prove ordinary policy ALLOW for this exact email before combining.
            captures = []
            original = boundary._policy
            class Capture:
                async def evaluate(self, request):
                    result = await original.evaluate(request)
                    captures.append(result.effect)
                    return result
            boundary._policy = Capture()
            for _ in range(3):
                result = await client.call_tool("send_email", EMAIL)  # C, identical benign body
                assert payload(result)["reason_code"] == "FLOW_DENIED"
            assert captures == ["ALLOW"] * 3
            assert env.calls["send_email"] == 1  # zero additional executions; 3/3 benign emails blocked
        other = context(session="unrelated-session")
        store.register_session(other.principal, known_clean=True)
        assert not (await call(create_local_protected_server(boundary, other), "send_email", EMAIL)).is_error  # D
    asyncio.run(scenario())
    assert env.calls["send_email"] == 2 and env.calls["get_order"] == 1
    denied = [e for e in flow_audit.events if e.decision == "DENY"]
    assert len(denied) == 3 and all(e.sensitivity == Sensitivity.CONFIDENTIAL for e in denied)


@pytest.mark.parametrize("mode", ["missing", "unknown", "corrupt", "unavailable", "forged-ref"])
def test_scenario_e_unknown_or_inconsistent_provenance_fails_closed(mode, monkeypatch):
    env, store, trusted, boundary, server, _, _ = build(register=mode != "missing", clean=mode != "unknown")
    if mode == "corrupt": store._sessions[("tenant-a", "session-a")] = None
    if mode == "unavailable": monkeypatch.setattr(store, "exposure", lambda _: (_ for _ in ()).throw(OSError("private-store-error")))
    if mode == "forged-ref":
        trusted = trusted.model_copy(update={"provenance_refs": (str(uuid4()),)})
        server = create_local_protected_server(boundary, trusted)
    result = asyncio.run(call(server, "send_email", EMAIL))
    assert result.is_error and not env.calls
    assert payload(result)["reason_code"] in {"FLOW_DENIED", "PROVENANCE_UNAVAILABLE"}


@pytest.mark.parametrize("field,value", [("artifact_id", "forged"), ("source_kind", "TRUSTED"),
    ("sensitivity", "PUBLIC"), ("trust_level", "TRUSTED"), ("parent_artifact_ids", []), ("provenance_refs", [])])
def test_agent_security_metadata_is_rejected(field, value):
    env, _, _, _, server, _, _ = build()
    result = asyncio.run(call(server, "send_email", {**EMAIL, field: value}))
    assert payload(result)["reason_code"] == "INVALID_ARGUMENTS" and not env.calls


@pytest.mark.parametrize("tool,arguments,reason", [
    ("get_order", {"order_id": "order-b"}, "CROSS_TENANT"),
    ("issue_refund", {"order_id": "order-a", "amount_cents": 5001}, "APPROVAL_REQUIRED"),
])
def test_existing_denials_do_not_create_exposure(tool, arguments, reason):
    env, store, trusted, _, server, _, _ = build()
    result = asyncio.run(call(server, tool, arguments))
    assert payload(result)["reason_code"] == reason and not env.calls
    assert store.exposure(trusted.principal).artifact_ids == ()


def test_refund_threshold_and_approval_preserved_after_exposure():
    env, _, _, _, server, _, _ = build()
    async def scenario():
        assert not (await call(server)).is_error
        for amount, error in [(5000, False), (5001, True)]:
            assert (await call(server, "issue_refund", {"order_id": "order-a", "amount_cents": amount})).is_error == error
    asyncio.run(scenario())
    assert env.calls["issue_refund"] == 1


@pytest.mark.parametrize("which", ["authorization", "flow", "provenance"])
def test_required_store_or_audit_failure_never_sends_email(which, monkeypatch):
    class FailedAudit:
        def record(self, event): raise OSError("synthetic-audit-secret")
    env, store, _, _, server, _, _ = build(auth_audit=FailedAudit() if which == "authorization" else None,
        flow_audit=FailedAudit() if which == "flow" else None)
    if which == "provenance": monkeypatch.setattr(store, "exposure", lambda _: (_ for _ in ()).throw(OSError("secret")))
    result = asyncio.run(call(server, "send_email", EMAIL))
    assert result.is_error and env.calls["send_email"] == 0


def test_failed_retrieval_tracking_withholds_output_and_poisons_session(monkeypatch):
    env, store, trusted, _, server, audit, _ = build()
    monkeypatch.setattr(store, "record_order", lambda *a: (_ for _ in ()).throw(OSError("private-error")))
    result = asyncio.run(call(server))
    assert result.is_error and "output" not in payload(result) and env.calls["get_order"] == 1
    assert audit.events[-1].execution_status == "FAILED"
    with pytest.raises(ValueError): store.exposure(trusted.principal)
    assert asyncio.run(call(server, "send_email", EMAIL)).is_error and env.calls["send_email"] == 0


@pytest.mark.parametrize("mode", ["timeout", "error"])
def test_ordinary_policy_failure_prevents_outbound(mode):
    class Broken:
        async def evaluate(self, request):
            if mode == "timeout": await asyncio.sleep(10)
            raise RuntimeError("synthetic-private-error")
    env, _, _, _, server, _, _ = build(policy_factory=lambda _: Broken())
    assert asyncio.run(call(server, "send_email", EMAIL)).is_error and not env.calls


def test_exact_trusted_destination_can_explicitly_accept_confidential():
    env, _, _, _, server, _, _ = build(allowed={Sensitivity.CONFIDENTIAL})
    async def scenario():
        await call(server)
        assert not (await call(server, "send_email", EMAIL)).is_error
    asyncio.run(scenario())
    assert env.calls["send_email"] == 1


def test_concurrent_retrieval_then_email_serializes_and_other_session_progresses():
    async def scenario():
        entered, release, email_started = asyncio.Event(), asyncio.Event(), asyncio.Event()
        env, store, trusted, boundary, server, _, _ = build()
        ordinary = boundary._policy
        class BarrierPolicy:
            async def evaluate(self, request):
                if request.tool_name == "get_order":
                    entered.set()
                    await release.wait()
                if request.tool_name == "send_email": email_started.set()
                return await ordinary.evaluate(request)
        boundary._policy = BarrierPolicy()
        async with Client(server, mode="legacy", cache=None) as a, Client(server, mode="legacy", cache=None) as b:
            retrieval = asyncio.create_task(a.call_tool("get_order", {"order_id": "order-a"}))
            await entered.wait()
            # Signal actual lock acquisition attempt rather than a timing sleep.
            from contextlib import asynccontextmanager
            original_session = store.session
            attempted = asyncio.Event()
            @asynccontextmanager
            async def observed(principal):
                if asyncio.current_task() is not None: attempted.set()
                async with original_session(principal): yield
            store.session = observed
            email = asyncio.create_task(b.call_tool("send_email", EMAIL))
            await attempted.wait()
            assert not email_started.is_set() and env.calls["send_email"] == 0
            other = context(session="isolated")
            store.register_session(other.principal, known_clean=True)
            assert not (await call(create_local_protected_server(boundary, other), "send_email", EMAIL)).is_error
            release.set()
            assert not (await retrieval).is_error
            assert payload(await email)["reason_code"] == "FLOW_DENIED"
        assert env.calls["send_email"] == 1
    asyncio.run(asyncio.wait_for(scenario(), 5))


def test_new_exposure_inside_authorization_audit_invalidates_previously_allowed_email():
    env, store, trusted, boundary, server, audit, _ = build()
    original = audit.record
    def expose(event):
        original(event)
        if event.execution_status == "AUTHORIZED":
            store.record_order(trusted.principal, boundary._registry.resource("order-a"), {})
    audit.record = expose
    result = asyncio.run(call(server, "send_email", EMAIL))
    assert payload(result)["reason_code"] == "FLOW_DENIED" and not env.calls


def test_mutated_invocation_after_policy_still_uses_authorized_snapshot():
    env, _, trusted, boundary, _, _, _ = build()
    proposal = ToolInvocation(server_id="support", tool_name="send_email", arguments=dict(EMAIL))
    ordinary = boundary._policy
    class Mutate:
        async def evaluate(self, request):
            decision = await ordinary.evaluate(request)
            proposal.arguments["recipient"] = "outside@example.test"
            proposal.arguments["body"] = "modified"
            assert decision.request_digest == request_digest(request)
            return decision
    boundary._policy = Mutate()
    result = asyncio.run(boundary.execute_authorized(proposal, trusted))
    assert result.status == "EXECUTED" and env.arguments == [("send_email", EMAIL)]


def test_flow_audit_and_diagnostics_exclude_raw_content(caplog, capsys):
    env, _, _, _, server, audit, flow_audit = build()
    async def scenario():
        await call(server)
        result = await call(server, "send_email", {**EMAIL, "body": "synthetic-private-email-882"})
        assert result.is_error
        return result
    result = asyncio.run(scenario())
    text = result.model_dump_json() + str(caplog.text) + str(capsys.readouterr())
    text += "".join(e.model_dump_json() for e in (*audit.events, *flow_audit.events))
    assert "synthetic-private-email-882" not in text and EMAIL["recipient"] not in text
    assert '"status": "paid"' not in text


@pytest.mark.parametrize("mode", ["exception", "undefined", "late"])
def test_flow_policy_errors_and_late_allow_cannot_dispatch(mode, monkeypatch):
    env, _, _, boundary, server, _, _ = build()
    guard = boundary._flow_guard
    def broken(request, state):
        if mode == "exception": raise RuntimeError("synthetic-policy-secret")
        return None if mode == "undefined" else True
    guard._policy.permits = broken
    if mode == "late":
        ticks = iter((0.0, 2.0))
        monkeypatch.setattr("app.provenance.tracker.time", type("Clock", (), {"perf_counter": staticmethod(lambda: next(ticks))}))
    result = asyncio.run(call(server, "send_email", EMAIL))
    assert payload(result)["reason_code"] == "PROVENANCE_UNAVAILABLE" and not env.calls


@pytest.mark.parametrize("which", ["tenant", "session"])
def test_other_binding_cannot_use_artifact_reference(which):
    env, store, trusted, boundary, server, _, _ = build()
    result = asyncio.run(call(server))
    reference = payload(result)["output"]["artifact_id"]
    other = context(tenant="tenant-b", session="other") if which == "tenant" else context(session="other")
    store.register_session(other.principal, known_clean=True)
    other = other.model_copy(update={"provenance_refs": (reference,)})
    # Use tenant-a resource/recipient for session test. For tenant test ordinary
    # authorization independently denies before the foreign reference matters.
    result = asyncio.run(call(create_local_protected_server(boundary, other), "send_email", EMAIL))
    assert result.is_error and env.calls["send_email"] == 0


def test_flow_audit_callback_new_exposure_invalidates_allow():
    env, store, trusted, boundary, server, _, audit = build()
    original = audit.record
    def expose(event):
        original(event)
        if event.execution_status == "AUTHORIZED":
            store.record_order(trusted.principal, boundary._registry.resource("order-a"), {})
    audit.record = expose
    result = asyncio.run(call(server, "send_email", EMAIL))
    assert result.is_error and not env.calls


def test_waiting_session_cancellation_releases_no_unowned_lock():
    async def scenario():
        env, store, trusted, boundary, _, _, _ = build()
        attempted = asyncio.Event()
        async def waiting():
            attempted.set()
            return await boundary.execute_authorized(ToolInvocation(server_id="support", tool_name="send_email", arguments=EMAIL), trusted)
        async with store.session(trusted.principal):
            task = asyncio.create_task(waiting())
            await attempted.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
            assert not env.calls
        result = await boundary.execute_authorized(ToolInvocation(server_id="support", tool_name="send_email", arguments=EMAIL), trusted)
        assert result.status == "EXECUTED" and env.calls["send_email"] == 1
    asyncio.run(scenario())


def test_atomic_dispatch_excludes_concurrent_trusted_metadata_write():
    from threading import Event, Thread
    env, store, trusted, boundary, server, _, _ = build()
    attempting, finished = Event(), Event()
    threads = []
    original = boundary._flow_guard._policy.permits
    def evaluate(request, state):
        def writer():
            attempting.set()
            store.record_order(trusted.principal, boundary._registry.resource("order-a"), {})
            finished.set()
        worker = Thread(target=writer)
        threads.append(worker)
        worker.start()
        assert attempting.wait(2)
        assert not finished.is_set()  # final-check transaction excludes the writer
        return original(request, state)
    boundary._flow_guard._policy.permits = evaluate
    result = asyncio.run(call(server, "send_email", EMAIL))
    for worker in threads: worker.join(2)
    assert finished.is_set() and not result.is_error and env.calls["send_email"] == 1
    # Writer linearized after dispatch. Its subsequent exposure denies later mail.
    boundary._flow_guard._policy.permits = original
    assert asyncio.run(call(server, "send_email", EMAIL)).is_error
    assert env.calls["send_email"] == 1


def test_failed_retrieval_has_no_success_artifact(monkeypatch):
    from dataclasses import replace
    env, store, trusted, boundary, server, _, _ = build()
    registry = boundary._registry
    from app.authorization.registry import ToolRegistry
    def failed(args): raise RuntimeError("synthetic-private-error")
    entries = [registry.resolve("support", name) for name in ("get_order", "send_email", "issue_refund")]
    boundary._registry = ToolRegistry([replace(entries[0], executor=failed), *entries[1:]],
                                     tuple(registry._resources.values()))
    result = asyncio.run(call(server))
    assert payload(result)["reason_code"] == "EXECUTION_FAILED"
    assert store.exposure(trusted.principal).artifact_ids == ()


def test_retrieval_audit_failure_keeps_confidential_exposure_and_no_output():
    class ExposureFailure(InMemoryFlowAuditSink):
        def record(self, event):
            if event.execution_status == "EXPOSURE_RECORDED": raise OSError("synthetic-audit-error")
            super().record(event)
    env, store, trusted, _, server, _, _ = build(flow_audit=ExposureFailure())
    result = asyncio.run(call(server))
    assert result.is_error and "output" not in payload(result)
    assert len(store._artifacts) == 1  # registered but never declassified/reset
    assert asyncio.run(call(server, "send_email", EMAIL)).is_error
    assert env.calls["get_order"] == 1 and env.calls["send_email"] == 0
