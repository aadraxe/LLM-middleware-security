# Groq MODEL_UNAVAILABLE diagnostic

## Findings and original evidence

**The existing metadata is insufficient to identify the original failure.** No actual provider root cause can be established without evidence that was not recorded. No new live request was made to obtain it.

Repository inspection started with a clean working tree on dotnet-middleware at fb42870e6698d0d5215f6d7a7180e97538d2b726. The supplied run is .agent-results/phase3d/a18022a5ac6b412cb2b57aa237a869fe/. Its saved JSON confirms order_lookup, llama-3.3-70b-versatile, one model invocation/HTTP-client attempt, zero MCP tool calls/executions, MODEL_UNAVAILABLE, no valid structured proposal and no validated token usage. The measured planning span was approximately 1,295.27 ms.

The adapter at that checkpoint converted all ordinary exceptions to the same fixed RuntimeError. The loop converted that exception to MODEL_UNAVAILABLE, while ProviderExchange retained only request-attempt/usage information. HTTP status, transport/parse category and provider error hints were lost. This diagnostic loss is confirmed; it is not evidence that the provider rejected any particular parameter or credential.

NO_VALID_STRUCTURED_PROPOSAL is a scorer observation: no validated proposal reached it. It does not prove Groq produced no proposal. A response could have been rejected by the local parser. provider_request_attempts=1 means the client entered its request attempt, not that a TCP/TLS connection, HTTP success or billed model execution completed. Null usage means no validated usage survived; absent/malformed usage alone does not cause the adapter to fail.

Under the inspected loop, discovery and the initial prompt-size check precede the recorded model attempt. The failure therefore occurred during model planning, before tools/call; it was not a tool authorization/provenance rejection. A normal expiry of the configured 10-second planner deadline is not suggested by a 1.3-second recorded span, but duration alone cannot identify an HTTP error, transport/platform failure or local response rejection. It must not be used to diagnose invalid credentials, account permissions, rate limiting or model retirement.

The recorded attempt flag rules out adapter validation/serialization failures occurring before client.stream was entered. One invocation under a two-call run budget also rules out budget exhaustion for this original run. Local nonblank-key configuration necessarily passed, but that says nothing about whether Groq accepted the credential. Remaining plausible paths are request/response transport, HTTP/provider error or response parsing/validation after the attempt began.

Original JSON/CSV files were not modified. Their SHA-256 values before/after inspection match:

| File | SHA-256 |
|---|---|
| evaluation.json | 4b1f2fb5d83956831b1d384206f53e0244da920000cf31cc0e25131e0d2166c6 |
| actions.csv | f56605388b3e618d90c6272217e281f34a55b8ed7adcd6f75ebd2e1ca8def55c |
| tasks.csv | a38155e74b5654cce504c84c4a2f88c1798423d9e94d8cf26d4a38add17e4193 |

## Possible failure paths

| Path | Why it could previously become MODEL_UNAVAILABLE | New safe metadata |
|---|---|---|
| Local request validation/schema JSON/serialization failure | Exception before HTTP, sanitized by the loop | request_invalid; request_attempted=false |
| Encoded provider request exceeds 131,072 bytes | Pre-request rejection | request_limit; no HTTP status |
| Client creation/context failure | HTTP client could not start | client_error |
| DNS/TLS/connect/write/read/protocol failure | httpx transport exception | transport_error; status only if already received |
| Provider HTTP failure, including 400/401/403/404/429/500 | raise_for_status previously discarded all safe status details | http_error; numeric status and fixed error hint |
| Unsupported, missing, inaccessible or retired model | Could appear as a provider error/HTTP failure | model_unavailable hint only when a known structured code supports it; HTTP 404 alone remains not_found |
| Non-JSON, ambiguous/duplicate-property or non-object JSON body | JSON-object contract rejected | invalid_json |
| Error envelope on a 2xx response | No ordinary completion could be consumed | provider_error plus allowlisted hint |
| Missing/wrong choices/message/assistant role or unsupported finish state | Completion shape rejected | invalid_response_structure |
| Parallel/mixed-content/malformed structured call, wrong field types, bad ID, invalid/duplicate argument JSON | Existing strict tool parser rejected | invalid_tool_call |
| Explicit finish_reason=length | Incomplete response rejected | truncated_response |
| Null/invalid/oversized final answer | Typed final-answer validation failed | invalid_final_answer |
| Response exceeds 65,536 bytes | Bounded read rejected | response_limit on successful status; known HTTP error retained for an oversized error body |
| HTTP-client timeout | Timeout exception from the provider transport | timeout |
| Outer planner deadline or late completion | bounded() times out/rejects a late result | planner_failure_category=timeout; adapter may separately report cancelled or success |
| Delegate/mock/wrapper error, missing propose method or exhausted run budget | Exception in the planner-await region | planner_failure_category=planner_error; existing BUDGET_EXHAUSTED status still takes precedence in evaluation |

Caller cancellation continues to propagate rather than becoming MODEL_UNAVAILABLE. Adapter cancellation is recorded as cancelled. A valid provider response arriving too late may have provider diagnostic success while the outer planner reports timeout; these describe different layers.

Other statuses must not be confused with this failure: a returned but invalid Decision produces INVALID_MODEL_OUTPUT; valid unknown tool names produce UNKNOWN_TOOL; decision-size violations produce RESPONSE_LIMIT; discovery/customer/prompt bounds fail before a model call; and tool errors/timeouts occur after an MCP call. A valid plain final response produces FINAL, never executes text and does not prove task completion. The saved zero-MCP run cannot have failed during a subsequent tool-result model turn.

## Request-format verification

The outgoing request was checked against [Groq Chat Completions](https://console.groq.com/docs/api-reference), [local tool calling](https://console.groq.com/docs/tool-use/local-tool-calling), the [selected model page](https://console.groq.com/docs/model/llama-3.3-70b-versatile) and [provider error documentation](https://console.groq.com/docs/errors). The model is still documented with tool-use capability; credential/account availability was not probed.

The existing fixed HTTPS endpoint, bearer authentication, application/json body, model ID, messages, tools/function/name/description/parameters shape, tool_choice=auto, parallel_tool_calls=false, temperature=0 and max_completion_tokens=1024 are documented request fields. A fixture obtains the actual three MCP schemas, verifies their object/required/property structure, then exercises assistant tool_calls and a tool-role response linked by tool_call_id.

**No concrete outgoing-request incompatibility was identified.** Request fields/model/provider were not changed. API documentation cannot establish account permissions or what the original request received. The existing parser intentionally accepts a narrower response subset: one complete native tool call without mixed text, or a completed typed final answer. It still rejects parallel/mixed/truncated/invalid structures. No arbitrary text parser, partial execution, tool-validation bypass or permissive fallback was added.

## New diagnostic fields and reporting

ProviderExchange adds optional fields, preserving older fixture/metadata construction:

- http_status: numeric 100-599, or null when no status was observed.
- diagnostic_category: fixed adapter-stage vocabulary, including success and the failure categories above.
- provider_error_category: fixed hint vocabulary; never an arbitrary provider code/type/message.

The adapter inspects only exact allowlisted error.code/error.type tokens from an ephemeral size-bounded error body. Examples map invalid_api_key to authentication_error, model_not_found/unsupported_model/model_decommissioned to model_unavailable, tool_use_failed to tool_generation_failed, and rate/quota hints to their fixed categories. Otherwise HTTP status provides a coarse safe fallback, or the hint is unclassified. A hint is evidence of the returned code/type/status, not independent proof of the underlying account/model problem. No regex over human error messages or request arguments is used.

summarize_usage now includes provider_diagnostics: ordered metadata records with an exchange ordinal, request-attempt flag, HTTP status and fixed categories. JSON task/summary records and tasks.csv carry these records. A CSV list is serialized as valid JSON rather than Python repr. Existing planner-await failures add planner_failure_category=timeout or planner_error to the action record/actions.csv. Successful/non-planner-failure action rows leave that field absent/null/N/A. Status MODEL_UNAVAILABLE and all existing execution decisions remain unchanged.

Exchange indices correlate serial provider invocations within each task; request_attempted distinguishes pre-request rejections. There is no backfill of old runs: new fields cannot recover discarded original evidence. Token metadata/coverage and null estimated-cost behavior are unchanged. Diagnostics never authorize an action and contain no model instructions or security grants.

## Security/privacy review

No raw response body, error message, failed-generation text, exception string, URL query, header, credential, customer prompt, final answer or tool arguments is stored in diagnostic metadata. Numeric statuses and constant allowlist outputs are the only provider-error evidence exported. An unrecognized string, object or malicious error-code value cannot be copied into the report. Tests include secret canaries and DEBUG-level HTTP logging capture.

Error bodies are read only into transient memory under the existing 65,536-byte response bound and existing client/outer deadlines. Status failures remain failures; no additional request, retry or redirect is performed. Reading bounded error data for a code/type hint is new; it does not relax authentication, output validation or time limits. A failure/cancellation while reading can leave the observed status alongside a transport/timeout/cancelled category; evaluate both fields together.

The 131,072-byte provider request bound, strict native tool parsing, fixed model/endpoint, interactive live controls, no environment credential discovery, safe default composition, authorization/provenance/audit ordering and no-retry guarantees remain intact. No credential input was requested/read and no provider API call was made. Public documentation browsing is the only external provider-related inspection. No dependencies, unrelated application modules, historical reports, .NET, RAG or models were changed.

## Tests and regression results

Exact commands:

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_groq_diagnostics.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_groq_diagnostics.py tests/test_groq_planner.py tests/test_llm_agent.py tests/test_live_evaluation.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
git diff --check
```

Final focused diagnostics: **34 passed**, zero failures/errors/skips/deselections, **2.12 seconds**. Combined diagnostic/provider/planner/live-evaluation fixtures: **154 passed** in **4.10 seconds**. Final full offline Python suite: **536 passed**, zero failures/errors/skips/deselections, **113.54 seconds**, exit code 0 (502 existing plus 34 new). git diff --check passed. The initial narrower combined run reported 100 passed/1 failed: the new diagnostic list was written to CSV as Python repr. The serializer was corrected to JSON-encode lists as well as dictionaries; the round-trip regression now passes. Counts overlap and must not be added.

Coverage includes HTTP 400, 401, 403, 404, 429, 500; known model/tool-generation/quota error hints; unknown/malicious codes; non-JSON/malformed/role-invalid/parallel/mixed-content/duplicate-argument/truncated/oversized responses; local pre-request failures; connect/read errors and timeouts; successful structured tool calls; actual MCP schema/role formatting; JSON/CSV privacy; outer deadline versus provider cancellation; and zero tool execution on HTTP failure. Existing strict-provider and agent cases remain enabled/unmodified.

Tests use httpx.MockTransport and the existing offline runner. Full/fixture execution uses the previously approved Windows context for pytest temporary-directory access, with real HTTP/external connections and downloads blocked. The initial diagnostic task performed no live requests, retries, commits, pushes, staging or Git configuration/identity changes. Subsequent finalization authorization is recorded below.

## Files changed

Modified: app/agent/llm/groq.py (failure-stage/status tracking and bounded allowlisted error hints), usage.py (optional metadata/report records), loop.py (separate outer timeout category), live.py (diagnostic CSV columns and list JSON encoding).

New: app/agent/llm/diagnostics.py (fixed vocabularies and allowlist), tests/test_groq_diagnostics.py, docs/AEGISFLOW_GROQ_DIAGNOSTIC.md. Seven files. The patch was initially left unstaged at fb42870 as requested. The separate finalization request authorizes the reviewed commit and normal push after verification.

## Finalization review — November 4, 2026

Reviewed all seven pending files. Changes are limited to fixed metadata diagnostics, JSON/CSV propagation, related offline tests and this report. Existing model/request fields, provider selection, credential controls, strict tool parsing, authorization, provenance, size/deadline bounds and no-retry behavior remain intact. The original run artifacts still match the hashes above. No new live Groq request was made.

Added one offline regression exercising the default-provider transport branch with its complete HTTP handler replaced by a local MockTransport fixture. Its simulated HTTP 403 failure is serialized into evaluation.json with http_status=403, diagnostic_category=http_error and provider_error_category=permission_error at both task and summary levels. The model remains unavailable and MCP execution count remains zero. This is simulated control-path evidence, not a live-provider test or result. Existing tests additionally verify CSV formatting, unknown/malicious error-value masking, DEBUG-log privacy, parsing failures, HTTP statuses and timeout-layer separation.

Final verification command:

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
git diff --check
```

Result: **537 passed**, zero failures/errors/skips/deselections, **27.41 seconds**, exit code 0 (502 pre-diagnostic tests plus 35 diagnostic cases). This completed run supersedes the earlier verification count for the finalized patch; overlapping runs are not added. Whitespace review passed. No pre-existing test was disabled or modified.

Configured author/committer identity was checked against the existing commit and effective Git identity without printing credentials or changing configuration. Only the seven reviewed text files are staged for the exact requested subject: `fix(groq): add privacy-safe provider diagnostics`. The resulting commit and verified normal push to origin/dotnet-middleware are recorded in terminal/final output after commit. No amend, rebase, force-push, main merge or PR is included.

## Remaining uncertainties

The original HTTP status, provider error hint, transport result, response shape and parser failure stage are unknown and unrecoverable from the saved metadata. Authentication, account/model access, tool generation failure, rate/quota limits, server failure and strict local response rejection remain possible. No actual root cause is claimed, and no request-format or credential fix is asserted.

Only a separately supervisor-approved future test with this metadata could distinguish those paths. Such a test must not be run automatically. Until then, provider/model compatibility and account access remain unverified; offline fixtures demonstrate classification and boundary behavior rather than live availability or robustness. Stop after this diagnostic task.
