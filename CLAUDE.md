# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Two layers that share one repository:

1. **Prompt-screening gateway** (original project): a FastAPI service (`app/main.py`, `app/check_api.py`) that classifies text as jailbreak/prompt-injection using regex + fuzzy rules, a fine-tuned DistilBERT classifier, and an optional Groq LLM judge. A .NET client (`dotnet/`, "LlmGuard") routes ASP.NET Core traffic through it.
2. **AegisFlow** (phased security work, `app/authorization`, `app/mcp`, `app/provenance`, `app/agent`, `app/output_security`, `app/retrieval`): action authorization, information-flow control, and output disclosure policy for an LLM agent that calls tools over MCP. Each phase has a report in `docs/AEGISFLOW_PHASE*_REPORT.md`; read the relevant one before changing a phase's code, since the reports record the threat model, trust assumptions and stated limitations the code must keep.

Text screening and action authorization are deliberately separate: an "allow" verdict from the gateway never authorizes a tool call.

## Commands

Python uses the repo's `venv` (Windows). Commands in docs are run with `-B` to avoid writing bytecode.

```powershell
pip install -r requirements.txt -r requirements-classifier.txt   # classifier deps optional
pip install -r requirements-mcp.txt                               # mcp==2.3.0, needed for AegisFlow tests

venv/Scripts/python.exe -B tests/run_offline.py                   # preferred: full suite, no network/secrets
venv/Scripts/python.exe -B tests/run_offline.py tests/test_provenance.py -q
venv/Scripts/python.exe -B tests/run_offline.py tests/test_cascade.py::test_name -q
pytest tests/ -v                                                  # plain run

uvicorn app.main:app --reload                                     # gateway, http://127.0.0.1:8000/docs
```

`tests/run_offline.py` strips `GROQ_API_KEY`, `GATEWAY_API_KEYS`, `PIPELINE_MODE`, etc. from the environment, forces HF offline mode, and blocks all non-loopback sockets and real httpx transports. `conftest.py` also neuters `dotenv.load_dotenv` so `.env` never leaks into tests, and redirects temp files to `.test-tmp/`. Tests needing the trained model in `models/` skip automatically when it is absent (the model is not committed).

.NET (from `dotnet/`, targets net8.0, C# 12 pinned in `Directory.Build.props`; CI in `.github/workflows/dotnet.yml`):

```bash
dotnet build LlmGuard.sln
dotnet test LlmGuard.sln                                   # in-memory fake gateway, no network
dotnet test LlmGuard.sln --filter "FullyQualifiedName~LlmGuardHandlerTests"
```

Evaluation entry points (all mock/offline unless noted; outputs go to ignored `.agent-results/<phase>/`):

```powershell
venv/Scripts/python.exe -B -m app.agent.evaluate                  # Phase 3B scripted workflows
venv/Scripts/python.exe -B -m app.agent.llm.evaluate              # Phase 3C mock planner over MCP
venv/Scripts/python.exe -B -m app.agent.llm.live --dry-run        # Phase 3D (live mode needs approval)
venv/Scripts/python.exe -B -m app.output_security.evaluate        # Phase 3E
venv/Scripts/python.exe -B -m app.output_security.public_evaluate # Phase 3F
venv/Scripts/python.exe -B -m app.retrieval.evaluate              # Phase 4A
venv/Scripts/python.exe -B -m app.retrieval.paired_benchmark --dry-run   # Phase 4B
venv/Scripts/python.exe -B -m app.retrieval.paired_fixtures
python benchmark/eval_cascade.py --no-judge                        # classifier/rule selection, no API calls
```

**Never run live provider modes** (`app.agent.llm.live --live`, `app.agent.llm.authorized --approved-live`, a live `paired_benchmark`) without explicit user instruction: they send data to Groq, may incur cost, and the docs require separate supervisor approval. Don't read or print `.env` contents.

## Gateway architecture

- `app/detectors/pipeline.py` picks the detection pipeline from `PIPELINE_MODE` (`local_only` default, `cascade`, `full`); legacy `CLASSIFIER_BACKEND` applies when the mode is unset. `app/gateway_state.py` holds the process-global lazy pipeline (`set_pipeline` is the test seam).
- `app/detectors/cascade.py` implements `local_only`/`cascade` routing using `cascade_config.json` (threshold 0.61, judge band 0.19–0.95, which rules may block vs. only escalate). That JSON is **generated** by `benchmark/eval_cascade.py` from the validation set; don't hand-tune thresholds or pick them from test-set results.
- `app/detectors/rules.py` reuses the regex/fuzzy definitions in `jailbreak_detector.py` and `prompt_injection_detector.py`; `judge_cache.py` wraps the Groq judge with a verdict cache keyed by prompt hash + template + model + temperature (`benchmark/judge_cache/`).
- Both `/secure-chat` and `/v1/check` require `X-API-Key` matching `GATEWAY_API_KEYS`. Security event logs (`app/logs/security_events.jsonl`) contain metadata only (length, SHA-256, verdict, layer, score, latency) — never prompt text, history or detector explanations. Errors return sanitized 503/502. Tests assert this; keep it.
- `rag/` is the original standalone Chroma retrieval + injection screening CLI, independent of `app/retrieval/`.

## AegisFlow architecture

Trust boundary: host code owns identity, policy, registry and configuration; model/planner/customer/retrieved text can only *propose*.

- **`app/authorization/`**: `ProtectedExecutor.execute_authorized(invocation, trusted_context)` is the single choke point for tool execution — registry lookup, schema validation, policy decision (`InMemoryPolicy`, with timeout), audit, then dispatch to fake tools (`fakes.py`, synthetic in-memory support environment). `TrustedContext`/`TrustedPrincipal` in `schemas.py` must come from host code, never from MCP arguments or model output.
- **`app/mcp/server.py`**: `create_local_protected_server(executor, trusted_context)` exposes only `get_order`, `send_email`, `issue_refund`; every `tools/call` delegates to the executor. Tool discovery is not authorization. No HTTP listener exists; the bound context is not production auth.
- **`app/provenance/`**: optional `ProvenanceGuard` passed to the executor as `flow_guard`. `ArtifactStore` tracks per-session exposure (e.g. reading an order marks the session CONFIDENTIAL); `FlowPolicy` maps (tenant, destination) to allowed sensitivities. Unknown exposure denies outbound flows. All executors in a session must share the same store/guard.
- **`app/agent/composition.py`**: `LocalApplication` is the host-owned factory wiring environment, store, audits, executor and MCP client; the default always enables provenance. `workflow.py` runs scripted plans; `llm/loop.py` runs a bounded planner loop (`run_agent` is internal; `run_customer_task` is the outward path). Planners: `llm/mock.py` (default) and `llm/groq.py` (`openai/gpt-oss-120b` only; retired models reject without fallback). `_unsafe_baseline.py` is a test-only comparison gated behind an explicit CLI flag.
- **`app/output_security/`**: `FinalResponseGuard` (Phase 3E) releases a generated answer only if the trusted recipient's policy allows the session's exposure, otherwise a fixed safe replacement. `public.py` (3F) issues a fixed host receipt before any planner/customer text; it is not a redacted answer and must not be conditional on confidential results.
- **`app/retrieval/`**: host-selected synthetic retrieval with tenant/read authorization (4A); retrieved text enters the planner as a separate lower-trust field and cannot choose tools, policies, labels or recipients. `paired_*` modules are the 4B benign/malicious paired benchmark (reports carry metadata only, not prompts/documents/answers).

Recurring invariants across these modules: strict Pydantic models (`StrictModel`), fail-closed on unknown/invalid state, explicit cancellation checks, metadata-only audit/report output, and no credentials read from the environment by live harnesses.

## Conventions

- Commits use Conventional Commits with a scope, e.g. `feat(security): ...`, `fix(groq): ...`.
- New AegisFlow phases add a `docs/AEGISFLOW_PHASE<N>_REPORT.md` and a README usage section; generated results stay in ignored `.agent-results/`.
- Large artifacts are ignored and rebuilt rather than committed: trained weights (`models/`, via `classifier/train.py`) and train/val/test splits (`data/build_dataset.py`, hashes in `data/processed/summary.json`).

## Rules for this repo
- Commits are authored by me. NEVER add Co-Authored-By, "Generated with Claude Code", session links or any AI attribution to commits or PRs.
- Never read, print or commit .env, API keys or AWS credentials. Ask me to run any command that needs credentials.
- Never push to main or force-push. Work on feature branches; I merge.
- Offline test suite: venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short (all tests must pass before any commit).
- The DistilBERT weights in models/distilbert are gitignored and must never be committed.
- Before any action that costs money or touches cloud resources, show me the plan and wait for my approval.
