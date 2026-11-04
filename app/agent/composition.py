"""Trusted local composition; default factory always installs provenance.

Only host code owns these objects. The workflow gets an SDK client connection
and a Plan, never context, registry, policy, environment or configuration.
"""
from contextvars import ContextVar
from dataclasses import dataclass, field
import time
from uuid import uuid4

from mcp import Client
from app.authorization.audit import InMemoryAuditSink
from app.authorization.executor import ProtectedExecutor
from app.authorization.fakes import FakeSupportEnvironment
from app.authorization.policy import InMemoryPolicy, PolicyConfig
from app.authorization.registry import support_registry
from app.authorization.schemas import TrustedContext, TrustedPrincipal
from app.mcp.server import create_local_protected_server
from app.provenance.flow_policy import FlowPolicy
from app.provenance.models import Sensitivity
from app.provenance.store import ArtifactStore
from app.provenance.tracker import InMemoryFlowAuditSink, ProvenanceGuard
from .models import Actor


@dataclass
class Measurement:
    boundary_ms: float = 0.0
    tool_ms: float = 0.0
    policy_ms: float = 0.0
    executions: dict = field(default_factory=dict)


# Instrumentation only, never an identity or authorization input.
_measurement = ContextVar("workflow_measurement", default=None)


class _MeasuredPolicy:
    def __init__(self, delegate): self.delegate = delegate

    async def evaluate(self, request):
        started = time.perf_counter()
        try:
            return await self.delegate.evaluate(request)
        finally:
            sample = _measurement.get()
            if sample is not None:
                sample.policy_ms += (time.perf_counter() - started) * 1000


class _MeasuredExecutor(ProtectedExecutor):
    """Always delegates to the real executor, with identical decisions/dispatch."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.samples = []

    async def execute_authorized(self, invocation, trusted_context):
        sample = Measurement()
        token = _measurement.set(sample)
        started = time.perf_counter()
        try:
            return await super().execute_authorized(invocation, trusted_context)
        finally:
            sample.boundary_ms = (time.perf_counter() - started) * 1000
            self.samples.append(sample)
            _measurement.reset(token)


class LocalApplication:
    """Host-owned scenario runtime; one shared environment/store across actors."""
    def __init__(self):
        self.environment = FakeSupportEnvironment()
        self.store = ArtifactStore()
        self.authorization_audit = InMemoryAuditSink()
        self.flow_audit = InMemoryFlowAuditSink()
        resources = self.environment.registry()
        def observed(name, target):
            def invoke(arguments):
                sample = _measurement.get()
                before = self.environment.calls[name]
                started = time.perf_counter()
                try:
                    return target(arguments)
                finally:
                    if sample is not None:
                        sample.tool_ms += (time.perf_counter() - started) * 1000
                        sample.executions[name] = sample.executions.get(name, 0) + self.environment.calls[name] - before
            return invoke
        self._registry = support_registry(
            get_order=observed("get_order", self.environment.get_order),
            send_email=observed("send_email", self.environment.send_email),
            issue_refund=observed("issue_refund", self.environment.issue_refund),
            resources=(resources.resource(name) for name in self.environment.orders))
        self._policy = InMemoryPolicy(self._registry, PolicyConfig(version="v1", refund_approval_threshold_cents=5000,
            approved_destinations=frozenset({("tenant-a", "support@example.test"), ("tenant-b", "support@example.test")})))
        self._guard = ProvenanceGuard(self.store, FlowPolicy({
            (tenant, "support@example.test"): {Sensitivity.PUBLIC, Sensitivity.INTERNAL}
            for tenant in ("tenant-a", "tenant-b")}), self.flow_audit)
        self.contexts = []

    def connect(self, actor: Actor):
        if not isinstance(actor, Actor):
            raise TypeError("trusted actor fixture required")
        actor = Actor.model_validate(actor)
        context = TrustedContext(principal=TrustedPrincipal(subject_id=actor.id, tenant_id=actor.tenant_id,
            roles=actor.roles, session_id=uuid4().hex))
        if actor.exposure != "missing":
            self.store.register_session(context.principal, known_clean=actor.exposure == "clean")
        self.contexts.append(context)
        executor = _MeasuredExecutor(self._registry, _MeasuredPolicy(self._policy), self.authorization_audit,
            policy_version="v1", flow_guard=self._guard)
        server = create_local_protected_server(executor, context)
        return Client(server, mode="legacy", cache=None), executor.samples

    async def run(self, actor: Actor):
        """Execute a trusted fixture's plan with only an MCP client in the agent."""
        from .workflow import failed_session, run_plan
        connection, samples = self.connect(actor)
        try:
            async with connection as client:
                return await run_plan(client, actor.plan, samples)
        except Exception:
            # No provider, argument or credential-bearing exception text in reports.
            return failed_session(actor.plan)


def create_application() -> LocalApplication:
    """Default protected experiment. No security-disable argument exists."""
    return LocalApplication()


def create_authorization_only_application() -> LocalApplication:
    """Explicit comparison: all invocation controls, no provenance restriction."""
    application = LocalApplication()
    application._guard = None
    return application
