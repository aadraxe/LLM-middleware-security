"""Offline synthetic evaluation. Unsafe baseline requires an explicit host CLI flag."""
import argparse
import asyncio
from collections import Counter
import csv
import json
import math
from pathlib import Path
import statistics
import time

from .composition import create_application, create_authorization_only_application
from .models import Scenario
from .scenarios import scenarios

DEFAULT_OUTPUT = Path(".agent-results/phase3b")


def percentile(values, percentage):
    """Linear interpolation at (n - 1) * p, including one-sample populations."""
    if not 0 <= percentage <= 100:
        raise ValueError("invalid percentile")
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentage / 100
    lower, upper = math.floor(index), math.ceil(index)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def rate(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None}


def summarize(rows):
    attempted = [step for row in rows for step in row["trace"] if step["mcp_attempted"]]
    prohibited = [step for step in attempted if step["ground_truth"] == "prohibited"]
    legitimate = [step for step in attempted if step["ground_truth"] == "legitimate"]
    executions = lambda step: sum(step["executions"].values())
    blocked = sum(executions(s) == 0 and s["status"] in {"DENIED", "APPROVAL_REQUIRED"} for s in prohibited)
    unauthorized = sum(executions(s) for s in prohibited)
    allowed = sum(executions(s) == 1 and s["status"] == "EXECUTED" for s in legitimate)
    incorrect = sum(executions(s) == 0 for s in legitimate)
    legit_tasks = [row for row in rows if row["legitimate_task"]]
    summary = {"tasks": len(rows), "attempted_actions": len(attempted),
        "skipped_actions": sum(s["status"] == "SKIPPED" for row in rows for s in row["trace"]),
        "prohibited_operation_block_rate": rate(blocked, len(prohibited)),
        "unauthorized_execution_rate": rate(unauthorized, len(prohibited)),
        "legitimate_action_allow_rate": rate(allowed, len(legitimate)),
        "legitimate_task_completion_rate": rate(sum(r["task_success"] for r in legit_tasks), len(legit_tasks)),
        "incorrect_block_rate": rate(incorrect, len(legitimate))}
    for field in ("security_enforcement_ms", "mcp_call_ms", "isolated_policy_ms"):
        values = [s[field] for s in attempted if s[field] is not None]
        summary[field] = {"samples": len(values), "median": statistics.median(values) if values else None,
                          "p95": percentile(values, 95)}
    return summary


async def evaluate_scenario(scenario: Scenario, factory=create_application, *, configuration="authorization_provenance"):
    if not isinstance(scenario, Scenario):
        raise TypeError("trusted scenario fixture required")
    scenario = Scenario.model_validate(scenario)
    application = factory()  # Trusted caller chooses factory; never read from task arguments/results.
    started = time.perf_counter()
    async def run(actor):
        result = await application.run(actor)
        for entry in result["trace"]: entry["actor_id"] = actor.id
        return result
    # Independent actors have separate fresh sessions but a common store/runtime.
    # TaskGroup cancels siblings on unexpected failure or caller cancellation.
    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(run(actor)) for actor in scenario.actors]
    outcomes = [task.result() for task in tasks]
    trace = [entry for result in outcomes for entry in result["trace"]]
    measured = Counter()
    for entry in trace: measured.update(entry["executions"])
    actual = dict(application.environment.calls)
    if dict(measured) != actual:
        raise RuntimeError("execution instrumentation mismatch")
    unauthorized = sum(sum(s["executions"].values()) for s in trace if s["ground_truth"] == "prohibited")
    return {"scenario_id": scenario.id, "configuration": configuration, "legitimate_task": scenario.legitimate_task,
        "task_success": all(result["complete"] for result in outcomes),
        "task_elapsed_ms": (time.perf_counter() - started) * 1000,
        "tool_calls": sum(s["mcp_attempted"] for s in trace), "execution_counts": actual,
        "unauthorized_operations_executed": unauthorized,
        "correctly_blocked_prohibited_operations": sum(s["ground_truth"] == "prohibited" and
            s["status"] in {"DENIED", "APPROVAL_REQUIRED"} and not sum(s["executions"].values()) for s in trace),
        "legitimate_actions_blocked": sum(s["ground_truth"] == "legitimate" and s["mcp_attempted"] and
            not sum(s["executions"].values()) for s in trace),
        "protocol_versions": sorted({r["protocol_version"] for r in outcomes if r["initialized"]}), "trace": trace}


async def evaluate(*, include_unsafe_test_baseline=False):
    configurations = [("authorization_only", create_authorization_only_application),
                      ("authorization_provenance", create_application)]
    if include_unsafe_test_baseline:
        from ._unsafe_baseline import create_unsafe_synthetic_test_application
        configurations.append(("unsafe_test_only", create_unsafe_synthetic_test_application))
    rows = []
    for name, factory in configurations:
        for scenario in scenarios():
            rows.append(await evaluate_scenario(scenario, factory, configuration=name))
    return {"schema_version": "1", "experiment": "deterministic_scripted_synthetic_mcp",
        "rows": rows, "summary": {name: summarize([r for r in rows if r["configuration"] == name])
                                  for name, _ in configurations}}


def write_reports(report, output: Path):
    """Write only metadata, counters and measured timings, never tool contents."""
    output.mkdir(parents=True, exist_ok=True)
    (output / "evaluation.json").write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    columns = ["scenario_id", "configuration", "actor_id", "step_id", "tool", "ground_truth", "status", "reason_code",
               "executions", "mcp_attempted", "security_enforcement_ms", "mcp_call_ms", "boundary_ms", "tool_ms", "isolated_policy_ms",
               "task_success", "task_elapsed_ms", "tool_calls", "unauthorized_operations_executed",
               "correctly_blocked_prohibited_operations", "legitimate_actions_blocked"]
    with (output / "actions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in report["rows"]:
            for step in row["trace"]:
                data = {**row, **step}
                writer.writerow({key: json.dumps(data[key], sort_keys=True) if key == "executions" else data[key]
                                 for key in columns})
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["configuration", "metric", "numerator", "denominator", "value"])
        for name, summary in report["summary"].items():
            for metric, value in summary.items():
                if isinstance(value, dict) and "rate" in value:
                    writer.writerow([name, metric, value["numerator"], value["denominator"],
                                     "N/A" if value["rate"] is None else value["rate"]])
                elif isinstance(value, dict) and "samples" in value:
                    for statistic in ("median", "p95"):
                        writer.writerow([name, f"{metric}.{statistic}", "", value["samples"],
                                         "N/A" if value[statistic] is None else value[statistic]])
                else:
                    writer.writerow([name, metric, "", "", value])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-unsafe-test-baseline", action="store_true",
                        help="explicitly add synthetic test-only baseline lacking authorization rules")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = asyncio.run(evaluate(include_unsafe_test_baseline=args.include_unsafe_test_baseline))
    write_reports(report, args.output)
    print(json.dumps(report["summary"], indent=2, sort_keys=True, allow_nan=False))
    print("Reports:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
