# Groq agent model compatibility fix

Reviewed November 4, 2026 on dotnet-middleware, starting from clean checkpoint cbfdbdf979e3453ad735390680c975dda320b4b2.

The supervisor reported HTTP 404 with model_unavailable from the retired model. Groq's [deprecation notice](https://console.groq.com/docs/deprecations) confirms that llama-3.3-70b-versatile was shut down for free/developer-tier usage on August 16, 2026 and recommends openai/gpt-oss-120b as a replacement. Enterprise committed-spend contracts have a different scope. This explains the reported tier-specific incompatibility; this task makes no new account/API probe and does not rewrite historical run artifacts.

GroqConfig now accepts only `openai/gpt-oss-120b`, and the evaluation CLI defaults/allowed model use that same ID. Explicit use of the old ID fails before credential/provider access. There is no automatic fallback or per-response model selection.

Groq's [model documentation](https://console.groq.com/docs/model/openai/gpt-oss-120b) lists tool-use support. Its [local tool-calling guide](https://console.groq.com/docs/tool-use/local-tool-calling) uses this ID with native function schemas, assistant tool_calls and tool messages linked by tool_call_id. The existing Chat Completions request matches that contract. The [API reference](https://console.groq.com/docs/api-reference) documents the existing tool_choice, parallel_tool_calls and max_completion_tokens fields. No request-format/parser relaxation is needed for the documented sequential subset.

Strict one-call parsing, duplicate/nonfinite JSON rejection, truncation rejection, fixed provider URL, output/step/time limits, 1,024 completion-token cap, no retries, explicit opt-in and hidden credentials remain unchanged. Authorization, MCP dispatch, provenance, diagnostics and metadata privacy are unchanged. No package, classifier/judge, gateway or security-policy change is included.

Tests assert the exact outgoing replacement ID and role-separated native tool messages, default dry-run model selection, deprecated configuration rejection and deprecated CLI rejection before credential/provider access. Existing malformed/parallel/truncated response, diagnostic, cancellation and protected-execution tests remain enabled. Fixtures use MockTransport and synthetic credentials only.

Full offline verification: `venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short` passed **539 tests in 30.60 seconds**, exit 0, with no failures, errors, skips or deselections. All 537 pre-existing cases are preserved (the requested 536 baseline was superseded by the prior diagnostic checkpoint's additional case); two new rejection tests are added. Execution uses the established approved Windows context for pytest temporary-directory access. `git diff --check` passed. The unchanged offline runner blocks live provider traffic and model downloads.

Changed files: app/agent/llm/groq.py, app/agent/llm/live_scenarios.py, tests/test_groq_planner.py, tests/test_live_evaluation.py, README.md, docs/AEGISFLOW_PHASE3D_REPORT.md and this note. Historical Phase 3C/diagnostic evidence remains unchanged. Source/staged review checks secret patterns and unrelated artifacts; Git identity/configuration is preserved.

No live Groq request is made. Account permissions, replacement-model quality, real response compatibility, token use and cost remain unverified. Reasoning may consume the existing completion budget and cause a fail-closed truncation; bounds are not increased. Live testing requires separate supervisor approval. No production authentication or new tools are added.
