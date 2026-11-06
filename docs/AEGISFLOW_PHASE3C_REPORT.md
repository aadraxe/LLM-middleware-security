# AegisFlow Phase 3C report

## 1. Scope and checkpoint

Initial working tree was clean on dotnet-middleware at 7a63f692692f6b2fc30bd9c345a7fc1f57de1840. The expected checkpoint, history and existing aadraxe/LLM-middleware-security origin were verified. Phase 2A/2B/3A/3B reports, actual agent/authorization/MCP/provenance source, llm_service.py, existing tests and requirements were inspected. No applicable repository AGENTS.md was found.

Added a separate optional planner integration under app/agent/llm/. The existing Phase 3B scripts/evaluation and security implementation are unchanged. No package installations, real provider calls, external model downloads, .NET/cloud/classifier changes, new MCP tools or production authentication were performed. Live-model evaluation: **NOT RUN**.

## 2. Model/planner interface

Planner.propose accepts a typed PlannerRequest and produces a Decision. Requests separate fixed application instructions, untrusted customer text, discovered tool definitions and lower-trust tool turns. Immutable canonical argument/schema/result strings prevent shared mutable dictionaries from becoming a policy input. Strict frozen models revalidate instances and reject extra fields.

A Decision is exactly one native structured ToolCall or a final answer. ToolCall includes an untrusted call ID, name and canonical JSON object arguments. Duplicate JSON properties and nonfinite JSON reject. There is no free-form text action parser. A final answer is untrusted text, never a grant, success assertion or executable instruction. It is available transiently to host code but excluded from Outcome serialization/repr and the evaluation report.

MockPlanner returns deterministic structured decisions (or deliberately invalid test values). Trusted test callbacks can examine the real prior MCP result and choose a next proposal, allowing explicit adversarial behavior without an LLM. These callbacks receive no tool executors, registry, policy or trusted identity. They do not establish real-world model planning or injection robustness.

## 3. Optional real-provider adapter status

The repository's existing llm_service.py uses Groq Chat Completions over httpx. The new GroqPlanner uses that existing dependency; it does not modify the legacy gateway service or its model selection. Provider-native tools/function definitions, assistant tool_calls and role=tool responses were checked against [Groq's local tool-calling documentation](https://console.groq.com/docs/tool-use/local-tool-calling) and [API reference](https://console.groq.com/docs/api-reference). The selected explicit model is llama-3.3-70b-versatile, documented for tool use in the [official overview](https://console.groq.com/docs/tool-use/overview) and [model page](https://console.groq.com/docs/model/llama-3.3-70b-versatile). Documentation was inspected on November 3, 2026, America/New_York.

GroqConfig requires enabled=True, the supported exact model ID and an operator-supplied SecretStr credential. GroqPlanner requires this typed configuration; it never reads environment keys or selects a provider automatically. There is no live-provider CLI option. A trusted host could construct it explicitly and pass it to run_customer_task; doing so can send synthetic customer/tool data to the provider. This phase made no such request.

The adapter fixes the HTTPS destination to api.groq.com/openai/v1/chat/completions, disables redirects/environment proxy settings, bounds request/response bytes and time, requests one sequential function call and performs no retries. It accepts one complete tool request or a completed final message; parallel, truncated, malformed or ambiguous responses fail closed. Provider bodies and exception details do not escape the fixed planner-unavailable error. Tests use httpx.MockTransport with synthetic credentials; no real transport is needed for the offline suite.

Status: **implemented and wire-fixture-tested; live compatibility/quality/cost NOT RUN**. Token usage and cost are null in evaluation artifacts because no trustworthy live provider measurements were collected. No pricing estimates or fabricated usage are reported. Tool schema advertisement is not authorization, regardless of provider validation.

## 4. Exact model security boundary and MCP flow

```text
Trusted host selects planner, Actor fixture and Limits
  -> Phase 3B create_application() (always provenance-enabled)
  -> fresh local principal/session -> existing protected MCP server + SDK client
  -> native tools/list -> exact get_order / send_email / issue_refund definitions
  -> PlannerRequest: trusted instructions | customer data | lower-trust tool data
  -> untrusted structured proposal
     -> strict decision/size/public-name/repeat checks
     -> client.call_tool(name, exact argument snapshot)
        -> existing MCP handler -> ProtectedExecutor
        -> strict schema + tenant/role/resource/destination/refund policy
        -> request-bound decision + required pre-execution audit
        -> existing provenance guard/session locks/final flow check
        -> registered fake tool only after every mandatory check permits
     -> fixed status and permitted synthetic output as lower-trust tool turn
  -> next bounded planner step OR untrusted final text OR fixed termination
```

Customer messages, proposed names/arguments, model answers and returned data are all untrusted. Neither the model nor its tool result can set identity/roles/tenant/session, policy version, labels, provider, approval token or security mode. Top-level model authority fields reject; extra tool arguments reach the existing strict MCP schemas and reject there. Unknown public tool names stop before any tools/call dispatch. No model-visible reset/declassification route exists. The integration does not import the unsafe comparison factory.

The loop passes no external decision/token to execution and invokes no fake function directly. The existing sole execution boundary receives every accepted public tool proposal. A denied call produces no alternate direct path. Schema normalization in the loop is used only to fingerprint repeats; ProtectedExecutor remains the actual validator/authorizer and dispatches its private argument snapshot.

## 5. Bounds, retries and termination

Trusted Limits defaults/caps:

| Control | Default | Hard configuration cap |
|---|---:|---:|
| Planner steps/model attempts | 8 | 16 |
| Customer bytes | 4,096 | 16,384 |
| Complete planner-request bytes | 65,536 | 131,072 |
| Validated decision bytes | 16,384 | 65,536 |
| Tool-result bytes forwarded to planner | 16,384 | 65,536 |
| Model deadline | 10 seconds | 60 seconds |
| MCP discovery/tool deadline | 2 seconds | 60 seconds |

Contracts also cap argument JSON at 16,384 characters, final answers at 8,192 characters and tool/call identifiers. The provider separately caps its encoded request at 131,072 bytes, response at 65,536 bytes and max_completion_tokens at 1,024. Size checks occur before the next model request or action dispatch where applicable. An oversized tool result may follow an already-executed read; it is withheld from the planner, with actual execution retained in the trace.

Call IDs cannot repeat. A tool plus canonical schema-normalized arguments cannot repeat in the same loop, even with a different ID or recipient casing. Requests are reserved before attempting them, including denied/uncertain calls. STEP_LIMIT stops distinct runaway requests. Changed arguments are distinct requests, not a promise of financial idempotency or semantic equivalence; existing financial/distributed exactly-once limitations remain.

Model timeout/error, invalid output, unknown tool, duplicate call, prompt/response/result bound and tool unavailability produce fixed termination statuses. Protected DENIED, APPROVAL_REQUIRED and fixed processing ERROR results are instead returned to the next planner turn as tool data. Text claiming approval cannot turn that status into execution; extra approval arguments still reject.

No automatic retries are performed. A timeout/unreadable tool response stops rather than inviting a side-effecting retry. The tool may already have executed before a response deadline; tests explicitly preserve the observed one-call count in that case. Cancellation propagates even if a planner suppresses CancelledError. Elapsed checks also reject late answers after cooperative timeout handling. Same-process blocking/cancellation-resistant code cannot be forcibly preempted; this is a local application boundary, not process isolation or hard real-time availability.

The safe host entry point sanitizes unexpected session failures and raises a fixed error instead of inventing zero-execution metrics. It does not retry, recreate a session or clear exposure after failure. It creates fresh trusted sessions only when explicitly invoked by host code for a new task.

## 6. Trusted versus untrusted conversation handling

The adapter serializes fixed instructions as system, customer text as user, structured proposals as assistant tool_calls and results as tool messages bound to call IDs. Returned instructions never become system messages. The mock injection test deliberately follows a malicious order field and proposes another tenant's lookup; actual authorization denies it. Another test requests email after an injected instruction to mark the order PUBLIC; actual confidential exposure remains and flow denies the send.

Tool-result sanitization preserves authorized synthetic data and fixed status/reason codes; it is not a universal prompt-injection scrubber. The model must see lower-trust result text for this experiment. No labels are inferred from its explanations, and no exact semantic provenance/declassification is added.

No raw customer input, email body, order dictionary, provider error body, API key or full transcript enters metadata traces/audits. Model final text is excluded from exported Outcome/report data. Existing authorization and flow audits remain unchanged. Transient planner memory and the existing synthetic recorder still contain authorized test data. Host code receiving final_answer must continue to treat it as untrusted text; final-answer correctness or confidentiality screening is outside this milestone.

## 7. Mock-agent tests and evaluation

Commands from repository root:

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_llm_agent.py tests/test_groq_planner.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_llm_agent.py tests/test_groq_planner.py tests/test_agent.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B -m app.agent.llm.evaluate
git diff --check
```

Final focused new tests: **67 passed**, zero failures/errors/skips/deselections, 2.45 seconds. The preceding combined run passed **134** (then-66 new plus all 68 unchanged Phase 3B cases) in 6.15 seconds. The last new case adds sanitized session-failure handling. The final full offline suite passed **449 tests**, zero failures/errors/skips/deselections, in **44.01 seconds**, exit code 0 (382 existing plus 67 new). git diff --check passed. Counts overlap; they must not be summed. No existing test is disabled or modified.

Cases cover valid order/email/refund; cross-tenant and role denial; approval-required/forged approval; authority-field injection; excluded/alias/reset tools; confidential-copy denial; harmless-email overblocking; embedded tool-result instructions; normalized repeated calls/IDs; runaway step bounds; all byte limits; ambiguous JSON; model error/timeout; late answer; tool timeout after execution; model/tool cancellation; independent shared-store sessions with deterministic ordering; final-text privacy; safe factory use; provider native wire/role formatting; malformed/parallel/truncated provider data; redirect/non-success/oversize failures; and explicit provider opt-in.

The first mock CLI smoke run completed its cases but emitted two Pydantic schema warnings (union-field repr metadata and a field shadowing schema_json). Both were corrected before test execution. Initial new tests passed 64; deterministic concurrency/tool-cancellation cases increased this to 66, then the session-error case to 67. There were no test assertion failures in this phase.

The unchanged offline runner clears inherited credentials/overrides, blocks live HTTP/external connections and model downloads, and permits asyncio loopback setup. Focused new tests pass in the restricted context. Combined/full runs use the already-established approved Windows context for pytest temporary-directory access. Provider fixtures replace transport entirely; no live credentials/services were accessed.

The separate mock evaluation exports metadata to ignored .agent-results/phase3c/evaluation.json. It does not alter or rerun into Phase 3B's output paths. Fifteen scenario entries include 13 structured decision sequences, a model timeout and independent concurrent sessions. Each records complete-task success from actual execution goals, unauthorized execution count, correct prohibited blocks, legitimate actions blocked, model/MCP calls, separate measured model/security/MCP times, final response status and null usage/cost. A model saying "complete" is not sufficient for task success.

The final mock command ran after the passing regression suite. Actual aggregate results from its artifact:

| Measurement | Observed result |
|---|---:|
| Scenario entries | 15 |
| Complete execution goals reached | 4/15 (mix of legitimate, attack and failure fixtures) |
| Entirely legitimate workflow goals reached | 4/5 (lookup, public email, refund, concurrent sessions succeed; harmless-after-read overblocks) |
| Unauthorized underlying tool executions | 0 |
| Correctly blocked prohibited proposals | 8 |
| Legitimate actions incorrectly blocked | 1 |
| Model calls | 32 |
| MCP tools/call attempts | 16 |
| Actual underlying executions | 9 |
| Live-model evaluation | NOT RUN |
| Token usage / cost | null / null |

The eight prohibited proposals include six rejected MCP invocations plus an unknown tool and a repeated request stopped by the loop before dispatch. They are explicitly defined by the mock fixtures, not inferred from the final answer. The other denied MCP call is the harmless-email false positive. Both confidential-disclosure and injected-result scenarios execute their initial read once, then execute zero prohibited downstream operations. Approval-required and unauthorized refunds execute zero times even when the final model text claims completion.

Measured local median latencies: **0.012550 ms** for 32 mock model calls, **0.330550 ms** for 16 protected enforcement spans and **0.879750 ms** for 16 end-to-end MCP calls. Full precision/per-call measurements are in the ignored artifact. Model time measures propose/await, including the timeout fixture; enforcement reuses Phase 3B's ProtectedExecutor span minus synchronous fake-tool time and excludes planner validation/repeat checks, provider time and discovery. MCP call time includes the SDK request/response and fixed result processing. These instrumented, tiny local samples are not production performance measurements. Mock planning latency is not comparable to scripted Phase 3B timing as an identical workload or production LLM latency.

## 8. Known limitations

- Mock proposals are predetermined adversarial/legitimate fixtures, not adaptive natural-language planning or real-model robustness measurements. Native MCP calls are real SDK memory interactions, not a remote deployment.
- Real Groq transport behavior, availability, token use, billed cost, answer quality and attack resistance were not measured. The implemented subset rejects parallel/mixed/truncated outputs rather than trying partial execution. Provider APIs/model support can change.
- Conservative session exposure can block harmless email after a confidential read. Exact text/span/semantic lineage and automatic declassification remain absent. Unmediated inputs, dishonest clean-session attestation or arbitrary host Python remain outside the guarantees.
- Repeated-call prevention is local to one bounded loop, not durable/distributed idempotency. Differently parameterized operations and new host-initiated tasks are distinct requests. No rollback can undo an already-run fake operation on response/audit failure.
- Model final text remains untrusted and is not a permission, correctness proof or policy-screened output channel. The current experiment protects tool dispatch and exports metadata rather than publishing full answers.
- Async deadlines are cooperative and cannot forcibly stop arbitrary blocking trusted code. Existing in-memory store/audit durability, session lifecycle and production authentication limits remain unchanged.

## 9. Files changed

New: app/agent/llm/__init__.py, contracts.py, mock.py, loop.py, groq.py, evaluate.py; tests/test_llm_agent.py; tests/test_groq_planner.py; docs/AEGISFLOW_PHASE3C_REPORT.md. Modified: README.md only (mock demonstration command). Ten scoped files. No existing agent workflow/evaluation, authorization, MCP, provenance, gateway/provider service, classifier, RAG, .NET, dependency or prior report was edited. Generated artifacts remain ignored by the existing .agent-results/ rule.

Full diff, metadata privacy, secret/artifact scope and configured author/committer identity are reviewed before staging/commit. Exact requested subject is feat(agent): integrate protected LLM tool planning. The resulting commit and verified normal push to origin/dotnet-middleware are reported in terminal/final output. Git identity/configuration is preserved; no attribution trailers, history rewrite, main merge or PR are part of this task.

## 10. Recommended Phase 3D scope

Architecture review should assess strict proposal validation, timeout/side-effect uncertainty, repeat semantics and lower-trust conversation handling. Select any live-provider experiment separately with explicit synthetic-data/credential authorization and recorded real model/usage details. Production identity, durable state and real-tool isolation remain separate reviewed work. Stop after Phase 3C; no AWS, Kubernetes, OPA, new tools, production authentication or deployment begins here.
