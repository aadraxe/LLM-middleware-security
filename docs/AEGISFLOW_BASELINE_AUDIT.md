# AegisFlow baseline audit

## 1. Executive Summary

Audit date: 2026-11-02 (America/New_York). Branch: `dotnet-middleware`. HEAD: `9a139e05fd4d8ed12bc0df2bb06fd171736f4bc6`. Working tree was initially clean. This is a local static audit with limited offline verification, not a deployed-system penetration test.

The repository implements prompt screening, not action authorization. Verified components include FastAPI chat and authenticated check endpoints, regex/heuristic jailbreak and injection detectors, a local DistilBERT wrapper, configurable classifier/judge routing, Groq judging, optional judge caches, separate Chroma retrieval screening, and opt-in ASP.NET Core/HttpClient interception. No MCP transport, tool dispatcher, OPA integration, trusted principal/session contract, tenant isolation, or enforced provenance-flow policy was found in application source.

Highest-priority confirmed issues are unauthenticated chat access, raw chat-prompt logging, .NET fail-open defaults, payload extraction gaps, and classifier-only fallback when an escalated judge check fails. Severity assumes network exposure of the affected service; actual deployment exposure was not verified. No Critical finding is established by the available evidence.

Verification: 78 Python detector/routing tests passed in a completed restricted run (3 deselected). A broader completed run reported 78 passed, 10 fixture errors, 12 deselected. An initial full run was interrupted and has no valid aggregate result. A pre-existing .NET Release test assembly reported 57 passed, 3 failed, 0 skipped; failures included Windows Event Log permission errors. The assembly was not rebuilt and cannot establish that current source passes. Local checkpoint files exist; successful model inference was not established. ChromaDB and sentence-transformers are absent from the inspected virtual environment.

Only this report is retained as a repository change. No application changes, package installations, deployments, AWS access, commits, pushes, or Git identity/configuration changes were performed. Stop here for architecture review.

## 2. Repository Inventory

53 relevant Python/C# source files were inspected through source reads, function/behavior searches, or test inspection, including root `conftest.py`; depth varied. This count excludes the notebook, configuration, documentation, datasets, saved results, dependencies, generated build output, model binaries and caches. Model binaries and Chroma database contents were not opened. Sensitive local `.env` values and dataset/document prompt contents were not reproduced. No applicable `AGENTS.md` was found in the repository search.

### Runtime implementation

| Exact path | Responsibility and verified status |
|---|---|
| `app/main.py` | FastAPI `app`, startup `lifespan`, `root`, `secure_chat`, `log_event`. Routes: `GET /`, `POST /secure-chat`; includes check router (21–35, 46–97). Standard FastAPI documentation/OpenAPI endpoints also remain enabled. |
| `app/check_api.py` | `POST /v1/check`; `require_api_key`, `decision_layer`, hash-based `_log_check`. Constant-time shared-key checks, reject if no configured keys (42–57, 78–102). Screening only; no LLM generation. |
| `app/gateway_state.py` | Process-global lazy pipeline via `get_pipeline`; test replacement via `set_pipeline` (11–24). No per-user state. |
| `app/models/schemas.py` | Chat/detection/pipeline/check Pydantic contracts. Chat accepts unbounded prompt/history (5–7); check text is 1–100,000 characters with user/rag source enum (41–44). |
| `app/services/llm_service.py` | `call_llm`; mock echo without Groq key; otherwise fixed Groq chat-completions destination, 30-second timeout, configurable model; exceptions become response strings (12–38). No history forwarding or output security check. |
| `app/detectors/base.py` | `BaseDetector` abstract `detect`, threat/threshold metadata and class-based `name` (12–24). |
| `app/detectors/pipeline.py` | `ThreatPipeline.analyze`, backend/mode resolution, startup directory prerequisite. Legacy backends llama/local/both/none; gateway modes local_only/cascade/full (18–70, 73–153). |
| `app/detectors/jailbreak_detector.py` | Seven regex families (instruction override, role manipulation, safety bypass, system prompt extraction, encoding, token smuggling, escalation primer); fuzzy leet/base64/unicode/entropy/length/persona/social engineering/multi-turn checks; `detect_jailbreak`, `JailbreakDetector`, optional `llm_judge` (18–138, 184–295, 316–421). Implemented, heuristic rather than authorization. |
| `app/detectors/prompt_injection_detector.py` | Five regex families (instructions in data, exfiltration, output manipulation, boundary attack, indirect injection); fuzzy exfiltration/task-switch/URL/fake-turn checks; `PromptInjectionDetector`, optional `llm_judge` (24–140, 162–249). |
| `app/detectors/rules.py` | `rule_hits` reuses regex/fuzzy definitions; `all_rule_names`, validation-based `split_rules` (24–75). |
| `app/detectors/cascade.py` | `CascadeConfig`, `route`, `local_only_decision`, `TieredPipeline`. Rule/classifier routing and optional judge with classifier fallback (33–131). |
| `app/detectors/cascade_config.json` | Committed validation-selected configuration: threshold .61, LOW .19, HIGH .95; three blocking rules; other listed rules are signals. Operational policy here is detection routing, not tool authorization. |
| `app/detectors/finetuned_detector.py` | `FineTunedClassifier` and `FineTunedDetector`; lazy torch/transformers imports, tokenizer/model loading, eval/no_grad, attack softmax index 1, 256-token truncation, optional threshold file (22–78). |
| `app/detectors/judge_cache.py` | Fixed Groq destination, temperature/model configuration, optional JSONL/legacy JSON caches, retry/backoff; no principal or tenant key in cache identity (28–65, 72–98, 105–183). |
| `rag/rag_core.py` | Module-level sentence-transformers embedding initialization, persistent shared `documents` collection and `chunk_text` (12–42). First embedding-model initialization may download. |
| `rag/ingest.py` | Local text-file chunking and Chroma insertion, source filename/chunk index metadata (16–43). Implemented CLI, not invoked by FastAPI. |
| `rag/query.py` | `retrieve`, top-N collection query and text/source/distance output (14–34). No user/tenant filter. CLI can print excerpts. |
| `rag/secure_retrieve.py` | Standalone `secure_retrieve`, screens retrieved text using its own `PromptInjectionDetector`, returns clean/flagged chunks (15–47). No generation stage or HTTP route. |
| `rag/_init_.py` | Unconventionally named initializer; not Python's conventional `__init__.py`. Namespace-package imports may still work; do not rename during audit. |
| `dotnet/src/LlmGuard/LlmGuardClient.cs` | `ILlmGuardClient.CheckAsync`, typed HttpClient calls `/v1/check` with API key; per-check timeout, response validation and failure-mode conversion (42–141). |
| `dotnet/src/LlmGuard/LlmGuardMiddleware.cs` | Incoming configured route-prefix POST/PUT/PATCH screening of one configured JSON string field; buffering, size cap, 403/503 outcomes; extraction failures continue downstream (36–149). |
| `dotnet/src/LlmGuard/LlmGuardHandler.cs` | Opt-in outgoing DelegatingHandler: extracts top-level prompt and textual message content, checks concurrently, throws before forwarding on block/FailedClosed. Tool/function response text is labeled rag; does not intercept tool execution (29–157). |
| `dotnet/src/LlmGuard/LlmGuardOptions.cs` | Gateway URL/key, 2-second timeout, empty default route list, prompt field, FailOpen default and 1-MiB incoming body limit (19–48). |
| `dotnet/src/LlmGuard/LlmGuardExtensions.cs` | DI/options binding, env key fallback, startup validation, middleware and handler registration (20–65, 79–107). Allows HTTP or HTTPS gateway URLs. |
| `dotnet/src/LlmGuard/GuardDecision.cs` | Outcomes, `IsAllowed` including FailedOpen, block/unavailable exceptions (4–70). |
| `dotnet/src/LlmGuard/PromptFingerprint.cs` | SHA-256 text fingerprint (10–11). |
| `dotnet/src/LlmGuard/Log.cs` | Structured logger methods; length/hash instead of raw prompt (11–27). |
| `dotnet/samples/ChatApi/Program.cs` | `/health`, `/chat`, incoming guard plus named outgoing guarded HttpClient; user-supplied history accepted, configurable provider or fake echo (19–108). Sample, not proof of deployed topology. |

### Research, tests and supporting files

| Exact path(s) | Responsibility/status |
|---|---|
| `classifier/__init__.py` | Package initializer. |
| `classifier/train.py` | Full fine-tuning or optional LoRA, seed 42, validation-selected threshold and model/results writes (40–220). Training can download pretrained models; not executed. |
| `classifier/metrics.py` | Confusion metrics, F1-based threshold search, JSONL loading (10–46). |
| `classifier/colab_train.ipynb` | Training notebook exists: 10 cells, 5 code cells; metadata inventory only, notebook execution/outputs not verified. |
| `data/build_dataset.py` | Downloads public datasets, normalizes/deduplicates, excludes deepset benchmark text, balances and stratifies train/validation/test, writes checksums (53–246). Not executed. |
| `data/tag_languages.py` | Seeded langdetect tagging with manual short-text overrides; CSV writer. Not executed. |
| `data/DATASET.md`, `data/processed/summary.json` | Dataset methodology and recorded counts/hashes. Local split hashes verified separately; upstream downloads not reproduced. |
| `data/processed/train.jsonl`, `data/processed/val.jsonl`, `data/processed/test.jsonl`, `data/processed/benchmark_200.jsonl`, `data/processed/benchmark_200_lang.csv` | Local fixtures exist. First three are gitignored. Contents not printed; checksum verification only for four JSONL files. |
| `benchmark/run_benchmark.py` | Legacy `ThreatPipeline` evaluation; local sample or Hugging Face dataset; seeded subset (20–155). `--sample` avoids dataset download but alone does not disable the judge. |
| `benchmark/sample_data.json` | Local sample fixture exists; not used for new benchmark measurements. |
| `benchmark/compare_classifiers.py` | Comparison configs a–e, cached judge timing, held-out seeded sample, result writers (64–205). Requires local model; optional live judge. |
| `benchmark/eval_cascade.py` | Validation rule split/band selection, judge/cascade comparisons and bootstrap CIs; writes runtime cascade config and results (126–502). Even `--no-judge` writes files; not run. |
| `benchmark/error_examples.py` | Reads saved prediction rows, writes sampled error report. |
| `benchmark/show_misses.py` | Prints missed examples; can download dataset and invoke judge. Not run. |
| `benchmark/suspected_mislabels.py` | Manual suspected-label annotations, CSV output; annotations do not establish corrected ground truth. |
| `readteam/garak_gateway_generator.py` | `gateway_generate`; local legacy pipeline then LLM, or explicit `REDTEAM_BASELINE=1` direct LLM (20–46). Directory really is `readteam`, despite redteam strings in usage documentation. |
| `readteam/analyze_results.py` | Garak report parser; estimates attack success from detector scores. Refusal/LLM behavior cannot alone establish gateway block counts (16–82). |
| `conftest.py` | Test import path and disables dotenv loading to avoid loading local secrets (1–9). Does not clear inherited environment keys. |
| `tests/test_jailbreak_detector.py`, `tests/test_prompt_injection.py`, `tests/test_pipeline.py` | Existing rule/fuzzy/aggregation tests; legacy hard-coded `/tmp/llm-security-enhanced` import-path insertion. Judge-enabled defaults require credential clearing for offline runs. |
| `tests/test_finetuned_detector.py` | Stub-classifier/backend tests and optional real-model smoke test. |
| `tests/test_cascade.py` | Stub routing, judge fallback, rule split/config and mode tests; missing-model temp fixture and optional real local pipeline. |
| `tests/test_check_endpoint.py` | Auth/validation/log privacy/contract tests using stub pipeline and temporary logs; optional real local-only endpoint smoke. Explicitly tests unauthenticated secure-chat behavior. |
| `dotnet/tests/LlmGuard.Tests/TestDoubles.cs` | In-memory fake gateway, recording provider and logger helpers. |
| `dotnet/tests/LlmGuard.Tests/LlmGuardClientTests.cs` | Contract/error/timeout/cancellation/log privacy tests. |
| `dotnet/tests/LlmGuard.Tests/LlmGuardMiddlewareTests.cs` | Route/extraction/size/failure-mode/options/log tests; unscreenable inputs intentionally pass through. |
| `dotnet/tests/LlmGuard.Tests/LlmGuardHandlerTests.cs` | Message extraction, concurrency, block/failure priority, pass-through tests. |
| `dotnet/tests/LlmGuard.Tests/ChatApiIntegrationTests.cs` | Sample app integration with fake gateway/provider; no live Groq needed. |
| `dotnet/benchmarks/LlmGuard.Overhead/Program.cs`, `dotnet/benchmarks/LlmGuard.Overhead/LlmGuard.Overhead.csproj` | In-memory paired guarded/unguarded benchmark against a real running gateway; not executed. |
| `results/experiments.jsonl`, `results/runs/distilbert/preds.json` | Saved training metrics/predictions. Historical artifacts, not new measurements. |
| `results/comparison_distilbert/comparison.json`, `results/comparison_distilbert/comparison.md`, `results/comparison_distilbert/errors.md`, `results/comparison_distilbert/rows.jsonl` | Saved comparison and error artifacts; prompt-bearing rows/errors were not reproduced in audit output. |
| `results/eval_cascade/results.json`, `results/eval_cascade/summary.md`, `results/eval_cascade/comparison.csv`, `results/eval_cascade/rule_stats.csv`, `results/eval_cascade/band_sweep.csv`, `results/eval_cascade/language_breakdown.csv`, `results/eval_cascade/errors_best.csv`, `results/eval_cascade/rows.jsonl`, `results/suspected_mislabels.csv` | Saved cascade results, validation choices, errors and language analysis; not rerun. |
| `benchmark/judge_cache/` | Existing legacy judge cache; excluded from individual content inspection. Shared model/template/text cache, not a provenance ledger. |
| `rag/documents/python_basics.txt`, `rag/documents/poisoned_doc.txt`, `rag/documents/llm_security.txt`, `rag/documents/cybersecurity_basics.txt`, `rag/chroma_db/` | Document fixtures and persisted SQLite/vector artifacts exist. Database not opened and prompt contents not reproduced. |
| `models/distilbert/config.json`, `models/distilbert/model.safetensors`, `models/distilbert/tokenizer.json`, `models/distilbert/tokenizer_config.json`, `models/distilbert/threshold.json` | Local ignored checkpoint files exist; config identifies distilbert, weights are 267,832,560 bytes. Presence is verified, inference compatibility is not. |

### Configuration and delivery

`requirements.txt` lists unpinned datasets, FastAPI, httpx, Pydantic, pytest, uvicorn and python-dotenv. `requirements-classifier.txt` adds unpinned torch, transformers, peft, sentencepiece and protobuf. Neither supplies ChromaDB/sentence-transformers or langdetect. `app/main.py:6–11` optionally loads `.env`; `.gitignore` excludes that file, models, virtual environments, logs, training splits, Python caches and .NET outputs. `.env` exists but was not read; no assertion is made about its values or repository history.

`dotnet/LlmGuard.sln`, `dotnet/Directory.Build.props`, `dotnet/src/LlmGuard/LlmGuard.csproj`, `dotnet/samples/ChatApi/ChatApi.csproj`, `dotnet/tests/LlmGuard.Tests/LlmGuard.Tests.csproj` define net8.0/C#12 with warnings as errors, the library, sample and tests. Test package versions are specified. `dotnet/samples/ChatApi/appsettings.json` selects localhost gateway, two-second timeout, `/chat`, and FailOpen. Provider configuration comes from host configuration; local values are not trust evidence. `dotnet/samples/ChatApi/Properties/launchSettings.json` is a local development launch artifact, not deployment proof.

`.github/workflows/dotnet.yml` is the discovered CI workflow: push trigger, read-only contents permission, SHA-pinned checkout/setup-dotnet actions, .NET 8 selection, restore/build/test. No Python CI, Dockerfile, tracked AWS/deployment infrastructure, or production service manifest was found. README references are intended usage, not verified deployment. `.vscode/` is local IDE configuration and was not executed. `README.md`, `MODEL_CARD.md`, `dotnet/README.md`, `LICENSE` provide project/model/package documentation; documentation test counts were independently distinguished from executed results.

## 3. Current Request Flow

```text
uvicorn app.main:app
  lifespan -> gateway_state.get_pipeline -> build_gateway_pipeline
  GET / -> root -> list stages
  POST /secure-chat -> ChatRequest -> secure_chat
    -> get_pipeline().analyze(prompt, conversation_history)
    -> log_event (raw prompt, result)
    -> blocked: ChatResponse(allowed=False), no generation
    -> allowed: call_llm(prompt) -> mock or Groq -> ChatResponse
  POST /v1/check -> require_api_key -> CheckRequest -> check
    -> get_pipeline().analyze(text) -> decision_layer -> _log_check
    -> CheckResponse (no generation)

build_gateway_pipeline:
  default local_only -> TieredPipeline.analyze
    -> rule_hits -> FineTunedClassifier.predict_proba
    -> local_only_decision -> PipelineResult
  cascade -> same rules/classifier -> route
    -> confident/blocking-rule decision OR jailbreak_detector.llm_judge
    -> judge failure: classifier threshold fallback
  full -> build_pipeline('both') -> ThreatPipeline.analyze
    -> JailbreakDetector.detect -> PromptInjectionDetector.detect
    -> FineTunedDetector.detect -> aggregate any block
  legacy backend: build_pipeline(llama/local/both/none)

ASP.NET configured incoming route
  -> LlmGuardMiddleware.InvokeAsync -> ExtractPrompt
  -> ILlmGuardClient.CheckAsync -> POST /v1/check -> next or reject
named/registered outgoing HttpClient
  -> LlmGuardHandler.SendAsync -> ChatPayload.ExtractMessages
  -> concurrent CheckAsync per extracted text -> send or throw

separate RAG CLI/library:
  ingest -> chunk_text -> get_collection -> collection.add
  secure_retrieve -> retrieve -> collection.query
    -> independent PromptInjectionDetector.detect per hit -> clean/flagged
```

1. **Interception begins** at the explicit FastAPI handlers (`app/main.py:55–60`, `app/check_api.py:93–96`), or installed .NET middleware/handler (`LlmGuardMiddleware.cs:36–43`, `LlmGuardHandler.cs:29–47`). There is no transparent interception of arbitrary Python/.NET tool calls.
2. **Security decisions** are content verdicts in `ThreatPipeline.analyze` (`pipeline.py:34–69`), `route`/`local_only_decision` and `TieredPipeline.analyze` (`cascade.py:51–72,103–130`). `/v1/check` shared-key authentication is separate (`check_api.py:46–57`); no action authorization exists.
3. **Order:** tiered rules evaluate jailbreak regex, jailbreak fuzzy, injection regex, injection fuzzy (`rules.py:32–39`); then the classifier runs even if a blocking rule already fired (`cascade.py:104–107`). Local mode uses blocking rules or .61 threshold, ignores signal rules. Cascade prioritizes blocking rule, score >= .95, signal escalation, score > .19 escalation, otherwise allow (`cascade.py:51–63`, config). Full/legacy pipeline runs detectors sequentially, without inter-detector short-circuit (`pipeline.py:34–35,90–98`). Each legacy detector blocks at regex or cumulative fuzzy >= .70. Jailbreak judge runs on every remaining prompt when enabled despite the borderline comment (`jailbreak_detector.py:367–406`); injection judge runs only when cumulative score >= .45 (`prompt_injection_detector.py:211–246`).
4. **Errors/timeouts:** normal classifier/rule exceptions propagate out of analyze, preventing the subsequent Python LLM call; no uniform error decision exists (`pipeline.py:35`, `cascade.py:104–105`, `main.py:57–86`). Missing checkpoint directory aborts startup; existence check does not validate files (`pipeline.py:146–153`, `main.py:21–26`). Judge exceptions/no key return a benign boolean sentinel (`jailbreak_detector.py:316–342`, `prompt_injection_detector.py:162–181`). Cascade recognizes specific reason prefixes and falls back to classifier (`cascade.py:112–120`). Default judge HTTP timeout is 15 seconds; optional caches enable up to eight attempts plus long backoff (`judge_cache.py:72–98,148–168`), with no end-to-end request deadline. .NET gives up after its two-second default and returns FailedOpen/FailedClosed (`LlmGuardClient.cs:46–98`); caller cancellation propagates. LLM-call exceptions become text in an allowed chat response (`llm_service.py:37–38`, `main.py:88–96`). Log-write failure occurs before generation and prevents forwarding (`main.py:72–86`).
5. **Forwarding without all checks:** yes for .NET failure defaults and skipped extraction, and for judge failures in legacy/cascade modes. Deliberate configured routing also skips stages, which is not by itself a bypass of the selected mode. Python unhandled detector errors do not silently forward.
6. **RAG relationship:** separate CLI/library, not a generation endpoint. No RAG call exists in `secure_chat`; `/v1/check` source=rag only logs a client-provided label and always analyzes the same text (`check_api.py:96–101`). Calling raw `retrieve` bypasses `secure_retrieve` (`rag/query.py:14–34`).
7. **.NET scope:** incoming POST/PUT/PATCH on configured prefix routes, one exact/case-sensitive configured JSON field; outgoing only HttpClients with `AddLlmGuardHandler`, textual messages/top-level prompt, including historical/system/tool-result text (`LlmGuardExtensions.cs:49–65`, middleware 100–147, handler 86–157). No response interception, MCP JSON-RPC parsing, tool-call arguments/permissions, filesystem or process execution interception. `tool_calls` are not extracted as actions.
8. **Other bypass paths:** unregistered HttpClients, direct `call_llm`, raw retrieval, unprotected methods/routes, and explicit research `REDTEAM_BASELINE=1` (`readteam/garak_gateway_generator.py:25–46`). These demonstrate opt-in coverage, not a remotely exploitable tool executor. The sample outgoing handler provides a second screen even if incoming extraction skips, but it shares the fail-open default.

## 4. Confirmed Security Findings

Severity reflects consequence under the stated scenario. All findings below are confirmed source behaviors; exploitation against a production deployment is unverified.

| ID / severity | Evidence / location | Realistic scenario | Mitigation / verification status |
|---|---|---|---|
| AF-01 **High**: unauthenticated generation | `app/main.py:55–86` has no auth dependency; contrast `app/check_api.py:93`. | A network caller invokes allowed prompts directly against secure-chat, consuming provider quota and bypassing access restrictions enforced only on `/v1/check`. | Authenticate all generation access; derive principal and tenant server-side; rate limits/quotas. Confirmed statically, with existing `test_secure_chat_needs_no_api_key`; endpoint test did not execute successfully in this audit. Network reachability requires deployment verification. |
| AF-02 **High**: raw prompt retention | `app/main.py:37–43,62–72` writes full prompt into a shared local JSONL file. | Ordinary users include secrets or private business text; anyone with log read/backup access receives that content, for allowed and blocked requests. | Replace with minimal structured audit metadata; redact and restrict retention/access. Reuse hash/length pattern of `check_api.py:78–90`; hashing is still correlatable. Confirmed source; no real prompts submitted. |
| AF-03 **High**: .NET default permits unscreened requests | `LlmGuardOptions.cs:33–44`, `LlmGuardClient.cs:93–98`, `GuardDecision.cs:32`, `LlmGuardHandler.cs:56–63`. Sample config also selects FailOpen. | Gateway outage, 401, timeout, malformed reply or oversized check text results in FailedOpen and provider execution. Two-second timeout can expire before a legitimate judge call. | Protected actions must fail closed; explicit environment-specific availability policy for legacy chat. Test with fake gateway and zero downstream executions. Confirmed source and existing tests; prebuilt tests are qualified separately. |
| AF-04 **High**: extraction gaps pass through even with FailClosed | `LlmGuardMiddleware.cs:73–78,100–147`; `LlmGuardHandler.cs:31–43,101–122,134–157`. | A consuming app accepts a different request schema, alternative method, newer provider `input` format or tool-call arguments; it processes data that the installed guard skipped. Missing/invalid JSON itself is exploitable only if downstream accepts it. | Per-endpoint schema adapters; reject unscreenable payloads on protected action paths; explicit tool invocation guard. Confirmed coverage gap; exploitability depends on consumer schema. No claim that sample accepts every skipped format. |
| AF-05 **High**: failed judge is not an enforced prerequisite | `jailbreak_detector.py:322–342,387–406`; `prompt_injection_detector.py:168–181,230–246`; `cascade.py:112–119`. | In legacy mode a below-threshold attack is allowed during judge outage; cascade signal/band cases below .61 are allowed after judge failure. | Typed unavailable result and explicit fail-closed policy where judge completion is mandatory; deterministic action authorization must remain independent. Confirmed source; stub fallback test passed. Default local_only does not use judge. |
| AF-06 **Medium**: insufficient input/work bounds | `app/models/schemas.py:5–7,43`; `LlmGuardHandler.cs:36–47`; `judge_cache.py:72–98`. | Large chat/history consumes parsing, regex, memory and logging resources; outgoing many-message payload fans out without a configured concurrency cap. Retry-enabled judges may continue working after client timeout. | Byte/text/history/message-count limits, bounded concurrency, deadlines, admission limits. Confirmed missing bounds, no load test or quantified DoS threshold. |
| AF-07 **Medium**: partial inspection of full forwarded text | `finetuned_detector.py:28–37,49–53`; both judge modules slice at `prompt[:2000]` (`jailbreak_detector.py:324–325`, injection 170–171); `llm_service.py:30`. | An attack outside the classifier's 256-token or judge's 2,000-character prefix can reach generation when full-text rules do not catch it. | Reject over-budget inputs or inspect bounded chunks with conservative aggregation; record coverage. Confirmed truncation mismatch; a concrete successful attack was not measured. Full-text regex checks still apply. |
| AF-08 **Medium**: retrieval lacks tenant/document authorization | `rag/rag_core.py:21–27`, `rag/ingest.py:35–38`, `rag/query.py:16–32`. | If reused for multiple tenants, the shared collection can return another tenant's chunks because neither tenant metadata nor access filter is supplied. | Trusted tenant metadata, access-controlled ingestion, enforced query filters and resource authorization. Confirmed absence; actual cross-user exposure requires a multi-user integration, absent here. |
| AF-09 **Medium**: permissive judge verdict parsing | `jailbreak_detector.py:332–338`, `prompt_injection_detector.py:172–178`, `cascade.py:113–119`. | JSON `{}` becomes a benign false verdict rather than unavailable; string booleans use Python truthiness; confidence is not validated for type/range/finiteness. An uncertain cascade decision can therefore accept a malformed but parseable response. | Strict schema with required boolean, finite bounded confidence and typed error state; no model authority over permissions. Confirmed parsing behavior; live model manipulation not tested. |
| AF-10 **Low**: error detail exposure and misleading success | `llm_service.py:35–38`, `main.py:88–96`; judge diagnostic printing at `jailbreak_detector.py:329–342`. | A provider error is returned in an allowed response; external error bodies/exceptions enter console diagnostics and could contain sensitive diagnostic material. | Safe client error IDs/status, sanitized diagnostics and explicit generation error state. Confirmed behavior; no credential leakage was observed or claimed. |
| AF-11 **Informational**: action/identity/provenance contracts absent | `schemas.py:41–51`, `check_api.py:96–102`, `LlmGuardHandler.cs:115–121`. | Treating an allowed text or caller-supplied source label as authorization would create a trust-boundary error in a future agent. Current code has no protected tool executor to exploit. | Add independent authenticated action policy and trusted lineage interfaces. Confirmed capability gap, not a present MCP vulnerability. |

Additional assessed areas: Python production outbound destinations are fixed Groq URLs; no request-controlled arbitrary URL fetch or confirmed SSRF was found. .NET gateway/provider URLs and benchmark gateway URL are operator configuration, not demonstrated attacker input (`LlmGuardExtensions.cs:84–87`, sample `Program.cs:25–30`). HTTP gateway configuration can expose keys/text on an untrusted network; enforce HTTPS for non-loopback deployments. No confirmed cross-session conversation store exists; client history is supplied anew and not forwarded to Python generation. Shared pipeline/model and judge caches contain no access-control identity. No server-side log-reading route or exposed database endpoint was found. Absence of authentication/tenant enforcement does not prove the local log/database is publicly accessible.

## 5. MCP Integration Opportunities

Smallest useful boundary: a new, isolated MCP adapter that normalizes a tool invocation, authenticates the caller, resolves a trusted registry entry, obtains a deterministic policy decision, and only then invokes a constrained executor. Do not reinterpret `CheckResponse.verdict` as a tool permission.

Reuse FastAPI router/schema conventions and the existing hash/latency event shape. Reuse detectors as optional advisory signals and preserve `/v1/check` and .NET contracts. Neither the current text gateway nor the outgoing .NET LLM-message handler can serve as an MCP execution reference monitor without a new action-aware interface.

OPA integration needs a `PolicyDecisionPoint.evaluate(AuthorizationRequest)` interface and an `OpaPolicyClient` with pinned policy entrypoint/version, short deadline, strict response validation and deny on unavailable/malformed/undefined decisions. Runtime MCP credentials must be held only by the protected executor; if agents can reach the upstream MCP server directly, a proxy is bypassable regardless of policy correctness. Block/mediate alternate network paths and bind grants to normalized tool/server identities and exact arguments.

Implement or explicitly reject relevant MCP operations: tool discovery does not grant execution; `tools/call` must authorize; initialization/notifications/control messages need protocol handling rather than blanket treatment as calls. Resource reads, prompts, sampling and server-initiated requests require explicit scope decisions before claiming comprehensive MCP support. An HTTP JSON endpoint carrying a tool name is only a contract/adapter prototype until real transport semantics are implemented and tested.

## 6. Provenance Integration Opportunities

Existing RAG filename/chunk metadata (`rag/ingest.py:35–36`) and .NET user/rag hints are useful ingestion signals, not authenticated provenance. `retrieve` currently drops stable chunk IDs from its public result (`rag/query.py:27–33`); future output should retain resource IDs and trusted metadata.

Introduce an immutable data envelope: `artifact_id`, `content_digest`, tenant, source kind, source resource ID, sensitivity, trust state, parent artifact IDs and producer. Populate at trusted ingestion/retrieval/tool boundaries. Unknown labels must remain unknown/untrusted; never allow callers or the LLM to upgrade them to trusted. Classification and origin are separate dimensions: a detector-clean document can still contain confidential data.

Evaluate source-to-destination rules against principal, input artifact labels, tool, normalized resource and destination identity. For example, a confidential artifact must not flow to a public network-send tool unless explicit policy permits that tenant/principal/resource/destination combination. Destination normalization and validation must precede authorization and execution; policy cannot rely on an LLM's description of a URL.

For LLM outputs, retain conservative lineage from all accessible sensitive inputs or classify output as unknown. Exact token/span provenance across arbitrary paraphrasing cannot be inferred from hashes, embeddings, citations or classifier scores. Conservative taint limits utility; precise provenance requires constrained transformations or independently verifiable mechanisms. Record this uncertainty rather than claiming exact information-flow tracking.

Add structured security audit events with request/decision IDs, trusted principal/tenant/session identifiers, tool/server/resource/destination IDs, argument and artifact digests, policy version, allow/deny/unavailable, reason codes, enforcement outcome and bounded latency. Exclude raw prompts/arguments/secrets. Bound retention and access; hashes alone are not anonymization. Correlate authorization with execution result without converting the event log into a source of authority.

## 7. Existing Tests and Benchmark Results

### Environment and safe execution

Inspection used `venv/Scripts/python.exe`: Python 3.13.9 (Anaconda build). System `python.exe` is separately located at `C:/Python38/python.exe` and was not used for tests. Module discovery found pytest, FastAPI, httpx, Pydantic, torch, transformers, datasets and peft; ChromaDB and sentence_transformers were missing. Discovery establishes installation presence, not import/inference success. .NET SDK installed: 9.0.301; project targets net8.0 and CI installs SDK 8. No packages were installed.

Existing tests were read before execution. Test credentials are synthetic fixtures. `conftest.py` disables dotenv; inherited Groq credentials were additionally removed in test processes. Python bytecode and pytest cache writing were disabled. Socket connection attempts were blocked in-process; model tests additionally used Hugging Face offline settings during the initial run. No live provider, AWS, dataset download, ingestion, training or benchmark execution was attempted. Python socket blocking is a guard for these inspected tests, not a general-purpose process sandbox.

Exact initial Python command (PowerShell, repository root):

```powershell
& venv/Scripts/python.exe -B -c "import os,socket; [os.environ.pop(k,None) for k in ('GROQ_API_KEY','GATEWAY_API_KEYS','PIPELINE_MODE','CLASSIFIER_BACKEND','LOCAL_CLASSIFIER_PATH','JUDGE_CACHE_JSONL','JUDGE_CACHE_DIR','CASCADE_CONFIG')]; os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1'); socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('Network disabled for audit')); socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('Network disabled for audit')); import pytest; raise SystemExit(pytest.main(['tests/','-q','-p','no:cacheprovider','--tb=no']))"
```

This run printed progress ending at an error and then stopped progressing during the model-inclusive portion; interrupted with Ctrl+C. No total/pass assertion is made for it. Model import/inference root cause remains unknown.

A subsequent broad command used the same environment clearing/offline settings, `socket.socket.connect` guard and pytest arguments, adding this exact selection:

```text
-k "not real and not default_gateway_pipeline_runs_local_only and not missing_model and not client and not invalid_requests and not tiered_layers and not threat_pipeline_layers"
```

Result: **78 passed, 10 errors, 12 deselected** in 1.39 seconds. The ten errors were the client-fixture endpoint tests: missing/wrong/any/no keys, rejected request, allow/block contract, source default, event privacy, unauthenticated secure-chat. They failed setting up temporary paths with PermissionError; the `not client` selector did not exclude tests merely because they depended on the client fixture. No endpoint behavior was validated by those errors.

Exact completed detector/routing command:

```powershell
& venv/Scripts/python.exe -B -c "import os,socket; os.environ.pop('GROQ_API_KEY',None); os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'; socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('Network disabled for audit')); import pytest; raise SystemExit(pytest.main(['tests/test_pipeline.py','tests/test_jailbreak_detector.py','tests/test_prompt_injection.py','tests/test_finetuned_detector.py','tests/test_cascade.py','-q','-p','no:cacheprovider','--tb=no','-k','not real_model_smoke and not default_gateway_pipeline_runs_local_only and not missing_model_gives_clear_error']))"
```

Result: **78 passed, 3 deselected**, zero failures/errors, 0.53 seconds. Deselected: real-model smoke, default real gateway pipeline, missing-model test requiring tmp_path. These counts overlap the previous run and must not be added. Skips were not reported in either completed run. Stub tests verify logic only, not classifier efficacy or deployed controls.

Exact .NET command:

```powershell
dotnet vstest dotnet/tests/LlmGuard.Tests/bin/Release/net8.0/LlmGuard.Tests.dll /logger:console /TestCaseFilter:"FullyQualifiedName~LlmGuard"
```

Result: **57 passed, 3 failed, 0 skipped, total 60**. Failure output showed inability to write the Windows `.NET Runtime` Event Log, including sample gateway-down fail-open/fail-closed tests. Do not attribute these failures solely to application logic or declare the source green. A prebuilt ignored assembly was used to avoid restores/build writes; its correspondence to HEAD was not verified. No dependency restore, build or fresh-source .NET test was performed. The normal CI sequence is restore/build/test, but it downloads/builds and was outside this audit's constraints.

Pytest's temporary-directory fallback created two empty `tmp*` probe files and `pytest-of-aarav` in the workspace. Probe files disappeared automatically. The empty inaccessible directory was removed using narrowly scoped approved cleanup; no recursive deletion was used. No test artifacts remain as intended changes.

### Historical results, not new measurements

`results/experiments.jsonl` records full fine-tuning of distilbert-base-uncased, two epochs, seed 42, max length 256, threshold .61 chosen on validation. Recorded train/validation/test sizes: 7,288 / 912 / 912; validation and test each balanced 456/456. The deepset benchmark has 200 prompts, 78 attacks and 122 benign. Local SHA-256 comparisons against `data/processed/summary.json` matched for train, validation, test and benchmark files. This verifies artifact identity relative to that manifest, not correctness of labels or upstream reproducibility.

| Saved experiment | Set | Recall | Precision | F1 | FPR |
|---|---|---:|---:|---:|---:|
| Fine-tuned alone (`experiments.jsonl`) | test, 912 | 92.54% | 95.26% | .9388 | 4.61% |
| Fine-tuned alone | deepset, 200 | 21.79% | 94.44% | .3542 | .82% |
| Local rules + classifier (`eval_cascade/summary.md`) | test_full | 92.8% | 94.8% | .938 | 5.0% |
| Cascade | test_300 | 95.6% | 91.0% | .932 | 10.6% |
| Cascade | deepset_200 | 29.5% | 100.0% | .455 | 0.0% |
| Judge alone | deepset_200 | 50.0% | 100.0% | .667 | 0.0% |

Saved cascade report uses gpt-oss-120b at temperature 0, validation rule split and LOW/HIGH .19/.95; its 95% CIs use 1,000 bootstrap resamples, seed 42. It records 500 judge verdicts and zero unparseable responses, not proof future judge errors are safe. Saved `comparison_distilbert/comparison.md` is a separate earlier comparison: all-stage deepset recall 50.0%, versus 52.6% reference in cascade summary. Do not merge these separate judge/timing runs into one measurement. Saved fine-tuned full-test metrics agree across artifacts, while latency varies by run.

`dotnet/README.md` historical overhead table describes 300 measured requests plus 20 warmups on an i5-12500H/Windows 11, with mean added latency 95.5 ms, classifier/gateway 90.1 ms, transport 5.2 ms, .NET middleware .19 ms. These documentation values were not reproduced; no raw overhead measurement artifact was independently established. Garak adapter/analyzer exist, but no newly verified defended-versus-baseline Garak result is claimed.

Reproduction constraints: preserve split hashes, seed, checkpoint/tokenizer/threshold, cascade config, judge template/model/temperature and cache settings. Dataset/model loader calls do not pin every upstream revision, Python dependencies are unpinned, ignored local weights are not available from Git alone, and provider behavior can change. Training notebook execution is unverified. Preserve all baseline artifacts and use separate output locations for future experiments; `eval_cascade.py` can overwrite runtime configuration even with no judge calls.

## 8. Recommended First Implementation

Recommend a separate, default-deny authorization contract and single MCP tool-dispatch boundary, initially using a fake protected tool. Do not change classifier logic, existing endpoints, .NET defaults or benchmark output in that first change. A fake-executor milestone demonstrates enforcement without introducing production upstream access; it must not be presented as completed MCP transport support.

Proposed files (not created by this audit):

```text
modify: app/main.py                      # register isolated router
new:    app/authorization/schemas.py     # strict normalized contracts
new:    app/authorization/context.py     # trusted identity/session resolver
new:    app/authorization/policy.py      # PDP interface + fail-closed adapter
new:    app/authorization/opa_client.py  # bounded, validated OPA request
new:    app/authorization/audit.py       # metadata-only security events
new:    app/mcp/proxy.py                 # protocol-aware interception/dispatch
new:    app/mcp/registry.py              # trusted server/tool/resource schemas
new:    app/mcp/executor.py              # sole protected execution boundary
new:    policy/aegisflow.rego            # explicit allow rules/default deny
new:    policy/aegisflow_test.rego       # policy unit tests
new:    tests/test_tool_authorization.py
new:    tests/test_mcp_proxy.py
new:    tests/test_security_audit.py
```

Conventional package `__init__.py` files may also be needed. Extend `app/models/schemas.py` only if shared compatibility types are needed; prefer the isolated module above. Later RAG provenance work would change `rag/ingest.py`, `rag/query.py`, `rag/secure_retrieve.py` and add `app/provenance/models.py` and a trusted label store. Existing .NET files need no first-step changes; later add an action-aware adapter rather than equating message screening with authorization.

Dependencies: existing FastAPI/Pydantic/httpx suffice for a contract and fake executor plus OPA HTTP client. OPA is a separate pinned runtime/test binary or service, not a Python package. A real MCP transport requires selection and pinned version of an appropriate SDK and supported transports after reviewer approval; no particular current SDK version is asserted here. Trusted identity needs an existing identity provider/JWT verification or authenticated workload transport integration selected for the deployment. Until configured, the new boundary must deny; synthetic principals are test-only.

Proposed versioned contracts:

```json
{
  "schema_version": "1",
  "request_id": "server-issued",
  "principal": {"subject": "trusted", "tenant_id": "trusted", "roles": []},
  "session": {"id": "trusted", "expires_at": "verified"},
  "action": {"server_id": "registry-id", "tool": "registry-tool", "operation": "invoke"},
  "resource": {"id": "normalized-resource", "destination_id": "registry-destination"},
  "arguments_sha256": "digest-of-canonical-validated-arguments",
  "input_artifacts": [{"id": "artifact-id", "trust": "unknown", "sensitivity": "unknown"}]
}
```

The external caller supplies only tool request data and verified credentials, never authoritative principal/roles/labels. The server builds the policy request. Schema-validated normalized arguments or minimal policy-relevant attributes must accompany the digest inside the trusted policy/executor boundary; a digest alone cannot support argument-level authorization. Do not log raw arguments.

```json
{
  "decision_id": "server-issued",
  "effect": "deny",
  "reason_codes": ["unknown_provenance"],
  "policy_version": "pinned-version",
  "request_digest": "bound-normalized-request-digest",
  "expires_at": "short-validity",
  "obligations": []
}
```

`unavailable` is an internal error outcome that maps to no execution, not allow. Unknown obligations deny unless implemented. Reject mismatched request bindings, expired grants and unexpected policy response fields/types as appropriate to a strict versioned contract.

Security invariants:

- Every protected execution crosses authorization immediately before dispatch; deny/error/timeout/missing context executes zero tools.
- LLM content may request an action but cannot set principal, roles, tenant, session grants, policy, tool registry or trusted provenance.
- Unknown server/tool/resource/destination/provenance is denied unless a narrowly scoped explicit policy permits unknown data for that action.
- Exact validated arguments, destination and resource are bound to the decision; no post-decision mutation or reusable unbounded allow tokens.
- Tool output is labeled at the trusted boundary; LLM-generated output inherits conservative lineage/unknown state.
- Classifier or judge allow cannot override policy deny. Direct upstream access and credentials are unavailable to the untrusted agent.
- Tenant/session binding, revocation/expiry and execution idempotency/replay policy are explicit; an audit-write failure behavior is defined before deployment.
- Existing `/v1/check`, .NET message screening and baseline metrics remain compatible and reproducible.

Verification tests: fake executor spy asserts zero calls for missing/forged identity, cross-tenant request, unknown tool, malformed arguments, denied destination, unknown provenance, policy timeout/error/undefined/malformed allow, unsupported obligation, expired/replayed/mismatched decision and argument mutation. Assert exactly one call on an authorized request, with the authorized arguments. Include benign and injected text with classifier forced to allow to prove policy independence; authorization must produce the same deny. Test real MCP `tools/call` routing and protocol lifecycle once transport is selected, alternate dispatch paths, resource/prompt operation scope, metadata-only audit privacy and tenant isolation. Run existing Python and freshly built .NET regression tests in a permitted offline-capable environment before merge. Test Rego decisions separately against the pinned OPA version.

Tradeoffs: opt-in isolated routing preserves behavior but does not secure pre-existing paths; proxy enforcement is meaningful only when upstream bypass is prevented. Fail-closed policy reduces availability; keep deadlines short and errors observable. A local OPA service adds operations work but cleanly separates deterministic decisions. Conservative provenance can overblock paraphrases; avoid unsupported precision claims. Introducing a generic agent framework or retraining DistilBERT is unnecessary for this first milestone.

## 9. Risks and Open Questions

- Which deployment exposure, identity provider, tenant model and session lifecycle are intended? Shared API keys authenticate possession, not end users or resource permissions.
- Which exact MCP servers, tools, transports, resources and destination classes must be protected? Can upstream access be prevented by network and credential isolation?
- What is the policy for stale decisions, revocation, replay, partial execution, audit unavailability and policy distribution failures?
- Which data sensitivity labels are authoritative, and which transformations can preserve exact lineage? Unknown content must not silently become trusted after a clean detector verdict.
- Is legacy fail-open behavior intentionally retained for chat while new tool actions always fail closed? Document that distinction explicitly.
- Checkpoint inference/import did not finish in the initial test run; a controlled model smoke test is still needed. No checkpoint is missing locally, but Git checkout alone omits the ignored weights and split files.
- Endpoint tests require a usable temporary directory. .NET results came from an unverified prebuilt assembly and encountered Windows event-logging restrictions; clean-source verification remains outstanding.
- Chroma/embedding dependencies and potentially cached embedding weights are missing/unverified. No RAG runtime, ingestion, retrieval, model download or stored-document access control was tested.
- Inspect production ingress, TLS, rate limits, log access/retention and secret delivery before making deployment-level claims. No AWS or external infrastructure was inspected.
- Static inspection covered all discovered relevant source paths with varying depth; generated dependencies, caches, DB/model binaries, sensitive configuration and raw prompt corpora were excluded. Notebook code was not reviewed as an executed system. No claim of exhaustive vulnerability absence is made.

## 10. Commands Executed and Files Changed

Read-only commands included `Get-Content` of the attached task brief and selected source/config/docs; `Get-ChildItem`/`Test-Path` for inventory/checkpoint/build artifacts; `rg --files` with exclusions; `rg -n` for definitions, routes, network calls, detector/error behavior and test cases; `Select-Object`, `Select-String`, and `Measure-Object` for bounded inspection. Source reads used numbered PowerShell output of the form `$n=0; Get-Content $p | ForEach-Object { $n++; "${n}: $_" }`. Git commands: `git status --short`, `git status --short --untracked-files=all`, `git branch --show-current`, `git rev-parse HEAD`, and `git ls-files` on environment/deployment patterns. No Git mutations occurred.

Environment probes: `Get-Command python,dotnet`, `dotnet --list-sdks`, `Get-Item Env:TEMP,Env:TMP`, and `venv/Scripts/python.exe -B -c` with `sys.version` and `importlib.util.find_spec` for dependency presence. A read-only Python JSON/hash probe compared dataset SHA-256s, counted notebook cells, listed checkpoint file sizes/model type and counted source paths. No credentials were printed. Test commands and outcomes are recorded exactly in section 7, including unsuccessful/interrupted runs.

Operational inspection failures: the first login-shell call printed a PowerShell profile language-mode error; later calls used `login:false`. A broad file listing was noisy due to judge-cache enumeration and was narrowed. A Windows wildcard passed literally to rg failed and was replaced by directory plus `-g '*.cs'`. Some tool output was truncated; targeted follow-ups were used for important behavior. An inaccessible pytest-created temporary directory caused file-search/status warnings until cleanup. These are audit-environment limitations, not application vulnerabilities.

Cleanup attempted only the two known empty temporary probe paths and the newly created empty `pytest-of-aarav` directory. Probe files were already gone. Empty-directory removal initially failed with access denied, then succeeded using explicit user-approved escalation:

```powershell
Remove-Item -LiteralPath 'C:\Users\aarav\OneDrive\Documents\LLM-middleware-security\pytest-of-aarav'
```

The report was created with `apply_patch`. Final intended/retained change: **only `docs/AEGISFLOW_BASELINE_AUDIT.md`**. Application code, lockfiles, datasets, models, baseline results, Git identity/history and repository name were not changed. No implementation follows this audit; architecture review is the next step.
