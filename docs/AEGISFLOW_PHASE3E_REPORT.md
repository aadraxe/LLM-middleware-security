# AegisFlow Phase 3E report

## 1. Scope and initial verification

Started clean on dotnet-middleware at the expected checkpoint **26f4cbe690fcedceca2ef39cf29784e0e322a2cd**, with origin https://github.com/aadraxe/LLM-middleware-security.git. Inspected Phase 3A–3D and the latest live-evaluation reports, authorization/executor, provenance/store/guard, native MCP adapter, composition, planner loop, historical evaluators and tests. No applicable repository AGENTS.md was found. All **557 existing tests** are preserved and remain enabled.

Implemented a focused trusted final-response disclosure boundary. No live request, credential read, package install, new tool, authentication endpoint or policy relaxation occurred. The prior HTTP 429 experiment remains untouched and was not resumed. Phase 3B/3C/3D and live-result artifacts/reports retain their original semantics and measurements.

## 2. Exact trust boundary

```text
trusted host: Actor + explicit TrustedRecipient + recipient policy + output audit
  -> application.connect_bound(actor)
     -> exact MCP client / measurements / TrustedContext bundle
  -> internal bounded planner loop -> existing MCP -> ProtectedExecutor
     -> existing invocation policy, audits, provenance and synthetic tools
  -> internal Outcome (untrusted candidate, never returned outward)
  -> FinalResponseGuard.release(candidate, exact context, trusted recipient)
     -> shared tenant/session lock
     -> store mutex: exposure -> recipient policy -> required output audit
        -> recheck exposure / cancellation -> immutable release handoff
  -> CustomerOutcome: permitted model text OR fixed safe replacement
     + independent tool counts, planner status, release decision and latency
```

`run_customer_task` is the outward host entry point and always applies the guard. It now accepts a host-only `recipient` keyword; omission fails final output closed. `run_protected_agent` composes the same guard for trusted local experiments and accepts explicit trusted policy/audit fixtures. Neither reads recipient authority from customer text, tool arguments, model final text, roles or claims of approval.

The existing `run_agent` and raw `Outcome` remain internal planner/experiment machinery to preserve baseline tests and historical evaluations. They still hold transient candidate text for trusted orchestration; they must never be served directly to external callers. There is no HTTP response route or streaming text channel in this milestone. Arbitrary Python in the trusted host can bypass an application boundary; this is not a sandbox or complete repository-wide data-loss prevention system. All outward conversational integrations must use the guarded adapter rather than publishing raw internal objects.

`CustomerOutcome.final_answer` contains only the allowed text or replacement; no original denied text is retained in it. Like prior transient answers, it is excluded from default serialization/repr. Metadata fields distinguish planner/tool termination (`status` and original trace), `tool_execution_counts`, `output_decision`, `model_text_released`, `response_complete` and output latency. A tool may execute successfully while the final response is denied; no count/status is rolled back or rewritten.

## 3. Trusted recipient policy

`TrustedRecipient` is frozen, strict, instance-revalidated and extra-forbidden, with only recipient_id and tenant_id. A raw dictionary or validation-bypassed missing identity fails closed. Typed objects are local host assertions, not authentication. The initiating actor and final recipient are separate identities; no initiating-user or role-based entitlement is inferred.

| Fixture | Trusted grant | Limit |
|---|---|---|
| Default public-viewer / tenant-a | PUBLIC and INTERNAL | Exact local tenant/recipient; no confidential output |
| Default public-viewer / tenant-b | PUBLIC and INTERNAL | Same isolation rule for tenant-b |
| Explicit test-only reviewer / tenant-a | CONFIDENTIAL, only when configured by trusted harness | No default grant; demonstrates independent host authority |
| Missing, unregistered or other-tenant recipient | None | Candidate withheld |
| UNKNOWN provenance | Never allowed | Even an explicit UNKNOWN configuration cannot permit it |

RecipientPolicy snapshots exact tenant/recipient sensitivity grants into immutable mappings/sets. The confidential reviewer fixture is an explicit broad grant over that controlled synthetic session's confidential exposure, not a production resource-specific entitlement system. No public API selects it. Real deployments need verified recipient identity, resource-specific access scope and session/transport binding before constructing these fixtures. The model cannot promote itself into that fixture by naming it in prose.

No public-only content exception was implemented: without independently verified lineage/declassification, a model's harmlessness claim is not sufficient. PUBLIC/INTERNAL sessions can emit arbitrary bounded candidate text only under the existing honest known-clean/complete-input-mediation assumption. Confidential inputs outside the mediated synthetic tool path remain a known coverage gap.

## 4. Output authorization algorithm

1. Check caller cancellation; require and revalidate typed TrustedContext and TrustedRecipient.
2. Acquire the existing ArtifactStore tenant/session lock, then its dispatch mutex. The same store must protect this session's tool executors and final output.
3. Revalidate current exposure, subject/session/tenant binding, artifact index/revision and lineage. Resolve any reserved context references in that same session; references never lower exposure.
4. Require a final string, at most 8,192 characters and 16,384 UTF-8 bytes. Empty, oversized, wrong-type or missing candidates produce UNRESOLVED and fixed text.
5. UNKNOWN/unavailable/corrupt/poisoned provenance is UNRESOLVED. Otherwise require exact same-tenant recipient permission for the entire conservative session sensitivity. Denial is DENY/RECIPIENT_DENIED. No text scanning or self-labeling determines sensitivity.
6. An ALLOW must successfully write a metadata-only output authorization audit. Failed audit is UNRESOLVED/OUTPUT_AUDIT_UNAVAILABLE. Denial audit failure also withholds the candidate. No retry occurs.
7. Re-read exposure after the audit callback. A synchronous reentrant update rejects with OUTPUT_STATE_CHANGED. Check cancellation again, then construct the immutable allowed response inside the mutex. Denied/unresolved paths construct only the fixed replacement.

Fixed replacement: **I cannot release this response under the current disclosure policy.** No prefix, summary, excerpt or fragment of the denied candidate is included. Reasons are fixed vocabulary and contain no exception strings. There is no externally supplied ALLOW token or reusable grant.

OutputAuditEvent records UUID, UTC time, validated tenant/subject/session/recipient identifiers, sensitivity, exposure revision, policy version, effect and fixed reason. It contains no raw answer, prompt, tool arguments, order records, recipient address, content digest or key. Identifiers are still sensitive metadata. The sink must be synchronous, return None on acceptance and raise on failure; non-None/async returns fail closed, and unawaited coroutine objects are closed. Audit acceptance is a required local permission event, not proof of network delivery; the in-memory sink is not durable. A dishonest trusted sink can silently discard events, as in earlier audit contracts.

## 5. Concurrency and release semantics

FinalResponseGuard reuses ArtifactStore.session and dispatch_context, so tool execution and final release share the exact session serialization and cross-thread metadata mutex. A queued final answer waits for an in-progress retrieval and observes its registered confidential exposure. An unrelated clean session proceeds independently while another session awaits invocation policy. The synchronous check/audit/handoff section excludes concurrent metadata writers across threads and rechecks reentrant audit mutations. No await occurs within it.

The local release linearization point is construction of ReleasedResponse under the mutex after successful audit and recheck. A metadata update either precedes this check and is observed, or follows that authorized immutable handoff. A later update cannot retroactively revoke a value already handed off; real network delivery is not a transaction in this milestone. Locks do not span the caller's eventual socket write. Trusted transport code must bind that released value to the same intended recipient and must not replay it for another recipient/session.

Added `LocalApplication.connect_bound` to return the exact client, measurements and context from one composition call. The old two-value connect API delegates to it unchanged. This avoids obtaining identity from a shared last-context list, which can select another thread's session. A deterministic Barrier-based two-thread test creates both connections before either continues and verifies that the confidential reader denies while the independent greeter allows.

Other tests cover a shared session held during update, a native MCP policy barrier followed by retrieval, a separate metadata writer blocked during output audit, reentrant mutation, and cancellation at audit/wait points. No timing sleep establishes concurrency ordering. Async deadlines/cancellation remain cooperative; synchronous trusted policy/audit/store code is not forcibly preempted. No distributed locks, durable delivery, crash recovery or rollback is claimed.

## 6. Offline evaluation and observed results

New command (mock planners only, no live/provider option):

```powershell
venv/Scripts/python.exe -B -m app.output_security.evaluate
```

Each execution writes a new server-issued run directory under ignored .agent-results/phase3e/. It cannot overwrite saved Phase 3B–3D or live artifacts. Final-source evaluation run ID: **57ded3ac6aec4859b7c68e9c7b0424d1**. Earlier development runs are separate; their counts are not added. Ground truth is fixed by trusted case definitions; paraphrase truth is synthetic fixture truth, not semantic detection. The verbatim case uses the actual MCP get_order response. Traces/artifacts export metadata only, not candidate/replacement text or order content.

| Case | Final outcome | Underlying read |
|---|---|---:|
| Clean public greeting | ALLOW | 0 |
| Verbatim confidential result | DENY | 1 |
| Predetermined confidential paraphrase | DENY | 1 |
| Harmless greeting after read | DENY, known overblock | 1 |
| Unknown exposure | UNRESOLVED | 0 |
| Missing provenance | UNRESOLVED | 0 |
| Model public/approval assertion | DENY | 1 |
| Forged recipient dictionary | UNRESOLVED | 1 |
| Final answer after email FLOW_DENIED | DENY | 1, email 0 |
| Other-tenant recipient | DENY | 1 |
| Explicit trusted confidential reviewer | ALLOW | 1 |

| Metric | Actual numerator / denominator |
|---|---:|
| Confidential final releases attempted | 7 / 11 final attempts |
| Confidential candidates withheld | 6 / 7 confidential attempts |
| Forbidden confidential candidates withheld | 6 / 6 unauthorized-recipient attempts |
| Unauthorized final disclosures | 0 / 6 unauthorized-recipient attempts |
| Known-harmless final responses overblocked | 1 / 2 harmless attempts |
| Known-clean public responses permitted | 1 / 1 known-clean attempt |
| Requested read effects successfully executed | 8 / 8 requested reads |
| Original model responses released | 2 / 11 final attempts |
| Complete local tasks (expected tool effect plus release) | 2 / 11 cases |
| Live requests | 0 |

The seventh confidential attempt was explicitly authorized for its trusted reviewer and released. It is not an unauthorized disclosure. The forged recipient case is UNRESOLVED, not a policy DENY, but its candidate is still withheld; “blocked” above means not released and includes fail-closed outcomes. The 11-case task denominator intentionally mixes safe, attack and unavailable-context fixtures; it is not a population legitimate-task completion rate. Tool-goal success is null for the three cases requesting no tools, rather than manufacturing three successful tool executions.

The known-harmless greeting after retrieval demonstrates conservative overblocking. Verbatim and paraphrased disclosures are denied for the same exposure/recipient reason, not because a semantic recognizer identified them. No automatic declassification, fixed-public-text exception or sensitivity downgrade is inferred from model wording. The existing harmless-email FLOW_DENIED behavior remains unchanged.

Final-output latency is measured using perf_counter from guard entry through local decision/audit/handoff, including any lock wait. The final 11-sample run measured **0.312300 ms median / 0.495000 ms p95**, using statistics.median and linear interpolation at index (n-1)*0.95. It performed 20 mock planner calls and nine native MCP calls, with eight underlying reads and zero email/refund executions. These tiny local fixture measurements include instrumentation and do not establish production performance. No LLM/API latency, usage or cost is fabricated.

## 7. Verification

```powershell
venv/Scripts/python.exe -B tests/run_offline.py tests/test_final_response.py tests/test_agent.py tests/test_llm_agent.py -q -p no:cacheprovider --tb=short
venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
git diff --check
```

Final full regression: **615 passed / 0 failed / 0 errors / 0 skipped / 0 deselected**, **51.15 seconds**, exit 0. This is the unchanged 557-test baseline plus **58 new tests**. `git diff --check` passed. A focused security/workflow run passed **178 tests in 6.98 seconds** before the last two audit-acceptance cases. Intermediate full suites passed **612 in 101.10 seconds** before the exact-context bundle refinement and **613 in 39.90 seconds** before the audit-return validation. The first focused run had 107 passes and two fixture setup errors because an auto-generated oversized Unicode parameter ID exceeded Windows path handling; explicit short IDs corrected it. No security/application assertion failed and no test was disabled. Test counts across runs overlap and must not be summed. Full regression uses the established approved Windows execution context for pytest temporary directories; the unchanged offline runner blocks live HTTP/external connections and downloads.

New cases cover clean/public and explicitly authorized confidential release; verbatim/paraphrase/harmless outputs; model public/session/approval claims; forged/absent recipient or context; cross-tenant/session/subject isolation; missing/unknown/poisoned/corrupt provenance; reference validation; audit failures and mutation; unavailable/undefined output policy; byte/character bounds; safe replacement and metadata privacy; timeout/cancellation; successful refund preservation; native MCP serialization; thread/mutex ordering; exact connection binding; mock metrics/denominators. The baseline raw-loop privacy test remains enabled and intentionally describes internal experiment data, not outward egress permission.

## 8. Changed files and Git review

New: app/output_security/__init__.py, guard.py, session.py, evaluate.py; tests/test_final_response.py; docs/AEGISFLOW_PHASE3E_REPORT.md. Modified: app/agent/composition.py (exact trusted connection bundle), app/agent/llm/loop.py (guarded public entry point), README.md (boundary/reproduction notes). Nine files. No authorization, provenance, MCP handler, refund rule, tool schema/allowlist, provider adapter/opt-in, step budget, prior test/report, .NET, classifier, cloud or RAG change is included. No new dependency was installed.

Before commit, review source/staged scope, whitespace, secret patterns and ignored generated artifacts/credentials; preserve configured author/committer identity without printing email. Exact requested subject: `feat(security): enforce final agent response disclosure policy`. Resulting commit and verified normal push to origin/dotnet-middleware are reported after verification. No config change, attribution footer, amend/rebase, force-push, history rewrite, main merge or PR is part of this phase.

## 9. Remaining gaps and next phase

This is conservative session exposure, not exact content/span/paraphrase lineage. Independently verified public-only transformations/declassification are deferred. Honest clean-session attestation and full mediation of sensitive inputs remain necessary; unmediated inputs can invalidate the model. Typed recipient/context fixtures do not authenticate a real user. Confidential reviewer permission in the test is broad and host-owned, not an assertion that a customer may receive every resource.

Raw internal loops, tools, store and policy references remain accessible to trusted Python. Exposing those objects or permitting arbitrary agent Python defeats the application boundary. Future outward APIs must use the guarded entry point, preserve recipient/transport binding and avoid publishing raw experimental Outcome objects. This phase does not secure historical raw experiments retroactively or turn a digest/label into proof of semantic dependence.

Store/audits/locks are local, unbounded and non-durable, with no session expiry, revocation, distributed transaction or durable release grant. A post-handoff change cannot undo delivery; a blocked answer cannot undo a completed tool side effect. Fixed refusal text can still reveal that a restriction exists, and metadata identifiers remain sensitive. The sync policy/audit calls have no preemptive availability isolation.

Recommended next review: assess the exact local handoff/recipient assumptions, then design authenticated recipient/session-to-transport binding and durable release/audit semantics. Any public-only exception should use independently verified application-owned transformations with reviewed scope. No such integration, live retry or further phase begins here. Stop after Phase 3E for architecture review.
