"""End-to-end scripted MCP experiment and independently specified metric checks."""
import asyncio
import csv
import json
import subprocess
import sys

import pytest
from pydantic import ValidationError

from app.agent.composition import create_application, create_authorization_only_application
from app.agent.evaluate import evaluate, evaluate_scenario, percentile, rate, summarize, write_reports
from app.agent.models import Actor, Plan
from app.agent.scenarios import MAIL, actor, scenarios, step
from app.agent.workflow import run_plan


@pytest.fixture(scope="module")
def report():
    return asyncio.run(evaluate(include_unsafe_test_baseline=True))


@pytest.mark.parametrize("name,index", [("authorization_only", 0), ("authorization_provenance", 1), ("unsafe_test_only", 2)])
@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.id)
def test_all_scenario_outcomes_and_native_mcp_counts(report, scenario, name, index):
    row = next(r for r in report["rows"] if r["scenario_id"] == scenario.id and r["configuration"] == name)
    assert row["task_success"] == scenario.expected_completion[index]
    assert row["protocol_versions"] and row["protocol_versions"][0] == "2025-11-25"
    assert row["task_elapsed_ms"] > 0
    counts = {}
    for trace in row["trace"]:
        for tool, count in trace["executions"].items(): counts[tool] = counts.get(tool, 0) + count
        if trace["status"] == "SKIPPED":
            assert trace["mcp_call_ms"] is None and not trace["executions"]
        else:
            assert trace["mcp_call_ms"] > 0
            assert trace["boundary_ms"] >= trace["tool_ms"] >= 0
            assert trace["security_enforcement_ms"] == pytest.approx(trace["boundary_ms"] - trace["tool_ms"])
            assert trace["isolated_policy_ms"] >= 0
        if trace["status"] in {"DENIED", "APPROVAL_REQUIRED"}:
            assert sum(trace["executions"].values()) == 0
    assert counts == row["execution_counts"]
    assert tuple(counts.get(tool, 0) for tool in ("get_order", "send_email", "issue_refund")) == scenario.expected_tool_executions[index]


def test_security_and_utility_denominators(report):
    for name, prohibited, unauthorized, legit_allowed, legit_total, completed, incorrect in [
        ("authorization_only", 5, 2, 11, 11, 5, 0),
        ("authorization_provenance", 7, 0, 10, 11, 4, 1),
        ("unsafe_test_only", 0, 7, 12, 12, 5, 0),
    ]:
        result = report["summary"][name]
        assert result["prohibited_operation_block_rate"] == rate(prohibited, 7)
        assert result["unauthorized_execution_rate"] == rate(unauthorized, 7)
        assert result["legitimate_action_allow_rate"] == rate(legit_allowed, legit_total)
        assert result["legitimate_task_completion_rate"] == rate(completed, 5)
        assert result["incorrect_block_rate"] == rate(incorrect, legit_total)
    protected = [r for r in report["rows"] if r["configuration"] == "authorization_provenance"]
    assert sum(r["unauthorized_operations_executed"] for r in protected) == 0
    assert sum(r["legitimate_actions_blocked"] for r in protected) == 1


def test_conservative_false_positive_is_distinct_from_intentional_disclosure(report):
    rows = {r["scenario_id"]: r for r in report["rows"] if r["configuration"] == "authorization_provenance"}
    for name, truth in [("harmless_after_read", "legitimate"), ("confidential_disclosure", "prohibited")]:
        assert rows[name]["trace"][0]["status"] == "EXECUTED"
        mail = rows[name]["trace"][1]
        assert mail["status"] == "DENIED" and mail["reason_code"] == "FLOW_DENIED"
        assert mail["ground_truth"] == truth and not mail["executions"]


def test_default_factory_has_no_disable_argument_and_rejects_forged_plan_fields():
    with pytest.raises(TypeError): create_application(provenance=False)
    with pytest.raises(TypeError): create_application(configuration="unsafe_test_only")
    for authority in ("roles", "tenant_id", "configuration", "sensitivity", "session_id", "policy"):
        with pytest.raises(ValidationError): Plan.model_validate({"steps": (), authority: "forged"})
    with pytest.raises(TypeError): create_application().connect({"id": "forged"})


def test_default_composition_never_imports_unsafe_baseline():
    # Fresh interpreter avoids test collection's explicit unsafe-comparison import.
    script = "from app.agent.composition import create_application; import sys; create_application(); assert 'app.agent._unsafe_baseline' not in sys.modules"
    result = subprocess.run([sys.executable, "-B", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_default_evaluation_excludes_unsafe_configuration():
    result = asyncio.run(evaluate())
    assert set(result["summary"]) == {"authorization_only", "authorization_provenance"}
    assert len(result["rows"]) == 24


def test_actual_disclosure_body_is_derived_from_mcp_result_but_not_in_trace():
    scenario = next(s for s in scenarios() if s.id == "confidential_disclosure")
    # Explicit authorization-only fixture lets us inspect the attempted copy.
    application = create_authorization_only_application()
    async def run():
        connection, samples = application.connect(scenario.actors[0])
        async with connection as client: return await run_plan(client, scenario.actors[0].plan, samples)
    result = asyncio.run(run())
    assert result["complete"]
    email = next(args for tool, args in application.environment.arguments if tool == "send_email")
    assert '"tenant_id":"tenant-a"' in email["body"] and '"status":"paid"' in email["body"]
    assert email["body"] not in json.dumps(result)


def test_concurrent_sessions_share_store_without_taint_contamination():
    scenario = next(s for s in scenarios() if s.id == "concurrent_sessions")
    application = create_application()
    row = asyncio.run(evaluate_scenario(scenario, lambda: application))
    assert row["task_success"] and row["execution_counts"] == {"get_order": 1, "issue_refund": 1, "send_email": 1}
    assert len({c.principal.session_id for c in application.contexts}) == 2
    sensitivities = {c.principal.subject_id: application.store.exposure(c.principal).sensitivity.value for c in application.contexts}
    assert sensitivities == {"reader": "CONFIDENTIAL", "mailer": "PUBLIC"}


def test_each_repeated_scenario_has_fresh_trusted_sessions():
    sessions = []
    def factory():
        application = create_application()
        sessions.append(application)
        return application
    scenario = scenarios()[0]
    for _ in range(2): asyncio.run(evaluate_scenario(scenario, factory))
    ids = [app.contexts[0].principal.session_id for app in sessions]
    assert len(set(ids)) == 2


def test_results_cannot_change_policy_or_source_labels():
    application = create_application()
    application.environment.orders["order-a"].update({"configuration": "unsafe_test_only", "sensitivity": "PUBLIC", "roles": ["admin"]})
    row = asyncio.run(evaluate_scenario(next(s for s in scenarios() if s.id == "confidential_disclosure"), lambda: application))
    assert row["trace"][1]["reason_code"] == "FLOW_DENIED"
    assert application.environment.calls["send_email"] == 0
    assert application.store.exposure(application.contexts[0].principal).sensitivity.value == "CONFIDENTIAL"


def test_mandatory_audit_failure_and_unknown_provenance_never_execute_email(monkeypatch):
    application = create_application()
    def fail(event): raise OSError("synthetic-sensitive-audit-error")
    monkeypatch.setattr(application.authorization_audit, "record", fail)
    row = asyncio.run(evaluate_scenario(scenarios()[1], lambda: application))
    assert row["trace"][0]["reason_code"] == "AUDIT_UNAVAILABLE" and not row["execution_counts"]


@pytest.mark.parametrize("exposure", ["unknown", "missing"])
def test_unknown_or_missing_state_never_becomes_public(exposure):
    application = create_application()
    profile = actor(step("mail", "send_email", MAIL), exposure=exposure)
    async def run():
        connection, samples = application.connect(profile)
        async with connection as client: return await run_plan(client, profile.plan, samples)
    result = asyncio.run(run())
    assert result["trace"][0]["status"] == "DENIED" and not application.environment.calls


def test_stop_continue_and_dependency_skip_are_explicit():
    async def run(on_failure):
        plan = Plan(steps=(step("foreign", "get_order", {"order_id": "order-b"}, on_failure=on_failure),
                           step("mail", "send_email", MAIL)))
        application = create_application()
        connection, samples = application.connect(Actor(id="agent", plan=plan))
        async with connection as client: return await run_plan(client, plan, samples), application
    stopped, app = asyncio.run(run("stop"))
    assert [s["status"] for s in stopped["trace"]] == ["DENIED", "SKIPPED"] and not app.environment.calls
    continued, app = asyncio.run(run("continue"))
    assert [s["status"] for s in continued["trace"]] == ["DENIED", "EXECUTED"] and app.environment.calls["send_email"] == 1


def test_workflow_transport_errors_are_sanitized():
    application = create_application()
    connection, samples = application.connect(scenarios()[1].actors[0])
    async def run():
        async with connection as client:
            async def fail(*args, **kwargs): raise RuntimeError("synthetic-private-transport-secret")
            client.call_tool = fail
            return await run_plan(client, scenarios()[1].actors[0].plan, samples)
    result = asyncio.run(run())
    assert result["trace"][0]["reason_code"] == "WORKFLOW_UNAVAILABLE"
    assert "synthetic-private" not in json.dumps(result) and not application.environment.calls


def test_cancellation_propagates_and_executes_no_tool():
    async def run():
        application, started = create_application(), asyncio.Event()
        class Waiting:
            async def evaluate(self, request):
                started.set()
                await asyncio.sleep(10)
        application._policy = Waiting()
        task = asyncio.create_task(evaluate_scenario(scenarios()[1], lambda: application))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert not application.environment.calls
    asyncio.run(run())


def test_initialization_failure_has_no_fabricated_tool_calls_or_latency(monkeypatch):
    from contextlib import asynccontextmanager
    application = create_application()
    @asynccontextmanager
    async def broken():
        raise OSError("synthetic-session-secret")
        yield
    monkeypatch.setattr(application, "connect", lambda _: (broken(), []))
    row = asyncio.run(evaluate_scenario(scenarios()[1], lambda: application))
    assert row["tool_calls"] == 0 and not row["execution_counts"] and not row["task_success"]
    assert row["trace"][0]["reason_code"] == "MCP_SESSION_UNAVAILABLE"
    assert "synthetic-session-secret" not in json.dumps(row)
    assert summarize([row])["security_enforcement_ms"]["samples"] == 0


def test_repeatable_outcomes_and_defined_timing_variability(report):
    repeated = asyncio.run(evaluate(include_unsafe_test_baseline=True))
    def discrete(value):
        if isinstance(value, dict):
            return {k: discrete(v) for k, v in value.items() if not k.endswith("_ms")}
        if isinstance(value, list): return [discrete(v) for v in value]
        return value
    assert discrete(report) == discrete(repeated)


@pytest.mark.parametrize("values,p,expected", [([], 95, None), ([4], 95, 4), ([1, 2, 3, 4], 95, 3.85),
                                             ([4, 1, 3, 2], 50, 2.5), ([1, 8], 0, 1), ([1, 8], 100, 8)])
def test_percentiles(values, p, expected):
    result = percentile(values, p)
    assert result is None if expected is None else result == pytest.approx(expected)


def test_empty_rates_are_na_and_latency_has_no_fabricated_samples():
    result = summarize([])
    assert result["incorrect_block_rate"] == rate(0, 0)
    assert result["security_enforcement_ms"] == {"samples": 0, "median": None, "p95": None}
    with pytest.raises(ValueError): percentile([1], 101)


def test_json_csv_round_trip_privacy_and_summary_rates(report, tmp_path, caplog, capsys):
    write_reports(report, tmp_path)
    loaded = json.loads((tmp_path / "evaluation.json").read_text(encoding="utf-8"))
    assert loaded == report
    with (tmp_path / "actions.csv").open(newline="", encoding="utf-8") as handle:
        actions = list(csv.DictReader(handle))
    assert len(actions) == sum(len(r["trace"]) for r in report["rows"])
    assert all(isinstance(json.loads(a["executions"]), dict) for a in actions)
    with (tmp_path / "summary.csv").open(newline="", encoding="utf-8") as handle:
        summary = list(csv.DictReader(handle))
    for row in summary:
        if row["metric"].endswith("_rate"):
            assert float(row["value"]) == int(row["numerator"]) / int(row["denominator"])
    text = "".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir()) + caplog.text + str(capsys.readouterr())
    assert '"tenant_id"' not in text and "Synthetic confidential order:" not in text
    assert MAIL["body"] not in text and MAIL["recipient"] not in text
    empty = {"rows": [], "summary": {"empty": summarize([])}}
    write_reports(empty, tmp_path / "empty")
    assert "N/A" in (tmp_path / "empty" / "summary.csv").read_text()


def test_private_audit_content_excludes_raw_order_and_email():
    application = create_application()
    row = asyncio.run(evaluate_scenario(next(s for s in scenarios() if s.id == "legitimate_multistep"), lambda: application))
    serialized = "".join(e.model_dump_json() for e in (*application.authorization_audit.events, *application.flow_audit.events))
    assert row["task_success"]
    assert MAIL["body"] not in serialized and MAIL["recipient"] not in serialized
    assert '"status":"paid"' not in serialized


@pytest.mark.parametrize("field,value", [("roles", ["admin"]), ("tenant_id", "tenant-b"),
    ("session_id", "new-clean-session"), ("configuration", "unsafe_test_only"),
    ("sensitivity", "PUBLIC"), ("policy", {"allow": True})])
def test_tool_argument_authority_cannot_disable_default_protection(field, value):
    application = create_application()
    plan = Plan(steps=(step("forged", "send_email", {**MAIL, field: value}),))
    async def run():
        connection, samples = application.connect(Actor(id="agent", plan=plan))
        async with connection as client: return await run_plan(client, plan, samples)
    result = asyncio.run(run())
    assert result["trace"][0]["reason_code"] == "INVALID_ARGUMENTS"
    assert not application.environment.calls
