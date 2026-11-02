# AegisFlow Phase 2A report

## 1. Executive summary

Implemented an isolated, internal deterministic authorization foundation. An agent proposes only a tool identity and arguments. Trusted application code supplies principal/session context, registry, resource ownership, policy configuration and audit sink. `ProtectedExecutor.execute_authorized` validates a private normalized snapshot, obtains and validates a request-bound policy decision, records the required pre-execution event, then dispatches one registered fake callable only for ALLOW.

DENY, REQUIRE_APPROVAL, missing context, unknown tools, invalid arguments, policy failures/timeouts, undefined/malformed/mismatched decisions and pre-execution audit failure invoke zero tools. Policy decisions cannot be submitted as agent permissions or reused across invocations. New focused tests: **77 passed**. Intermediate complete offline Python runs passed **203 tests**; final-source verification after the caller-cancellation guards is recorded in section 9.

No HTTP endpoint, selectable fake HTTP identity, real MCP, OPA, agent/LLM integration, provenance enforcement, cloud deployment or external tool was added. No existing source/configuration, classifier/model, routes, .NET implementation, RAG scanning, datasets, benchmark artifacts or prior reports were modified. No dependencies were installed, no live external services were accessed, and no commits/pushes or Git identity/configuration changes occurred.

## 2. Final module structure

```text
app/authorization/
  __init__.py       internal-package scope and composition contract
  schemas.py        strict identity, invocation, arguments, request, decision/result
  registry.py       trusted registry, argument schemas, executor references, resources
  policy.py         PolicyDecisionPoint and deterministic in-memory policy/config
  executor.py       ProtectedExecutor.execute_authorized; sole local dispatch path
  audit.py          separate authorization event/sink contracts and in-memory sink
  fakes.py          synthetic customer-support tools and invocation records
tests/test_authorization.py
docs/AEGISFLOW_PHASE2A_REPORT.md
```

Only those nine files were created. The package uses existing Pydantic (installed 2.13.4) and the Python standard library. No FastAPI router imports it. All prior pending modifications remain in the working tree unchanged by this phase.

## 3. Authorization trust boundary

Three actors are explicit:

1. **Agent:** supplies `ToolInvocation(server_id, tool_name, arguments)` only. Extra principal/tenant/role/session/policy/decision/registry/provenance/classifier-authority fields are rejected.
2. **Trusted application:** constructs `TrustedContext` and supplies a configured `ToolRegistry`, `PolicyDecisionPoint`, policy version/timeout and `AuthorizationAuditSink` to the executor. Resource owners and per-tool required roles come from this trusted composition, never agent arguments.
3. **Protected executor:** exposes `execute_authorized`, accepting no external decision/token. It alone dispatches resolved callable references in this milestone.

`TrustedContext` must be an internal typed object, not an agent-provided dictionary (`executor.py:53–61`). It and its nested principal are revalidated; model instances created with validation bypass helpers do not become trusted simply by passing an isinstance check. Frozen nested objects, frozenset roles and tuple provenance references prevent ordinary in-process mutation. Registry dictionaries are read-only snapshots and registrations are frozen records (`registry.py:17–47`).

This is an application trust boundary for untrusted proposals, not a Python sandbox. Trusted code must never deserialize agent JSON into a TrustedContext, expose registry/executor references to the agent, or let it execute arbitrary Python in the trusted process. In-process malicious code can directly import/call fake functions or replace private attributes; no claim is made to prevent that. Identity authentication/session issuance is deliberately not implemented: existing shared API keys do not establish the new end-user principal automatically, and no HTTP identity adapter was added.

## 4. Data models and policy decision contract

`schemas.py:19–21` sets extra=forbid, strict=True, frozen=True and instance revalidation for the security models.

| Model | Actual fields and validation |
|---|---|
| `TrustedPrincipal` (`schemas.py:23–27`) | subject_id, tenant_id, frozenset roles, session_id; bounded ASCII identifiers. No inferred admin privilege or coercion from role lists in internal Python objects. |
| `TrustedContext` (`schemas.py:30–34`) | Typed principal and optional tuple provenance_refs. Absent references remain None/unknown. |
| `ToolInvocation` (`schemas.py:37–41`) | Bounded server_id/tool_name and JSON-valued arguments dictionary; no authoritative fields. Mutable untrusted arguments are immediately revalidated/snapshotted before policy use. |
| Argument schemas (`schemas.py:44–68`) | Order ID required. Email recipient has a bounded synthetic-address format and lowercase normalization; nonblank body <=8,192 characters. Refund amount is a strict positive integer of cents <=100,000,000; strings, booleans and fractional/negative values reject. Extra arguments reject. |
| `ResourceInfo` (`schemas.py:71–73`) | Resource ID/tenant supplied by trusted catalogue, never by agent ownership claims. |
| `AuthorizationRequest` (`schemas.py:76–94`) | Server UUID request_id, principal, registered server/tool, canonical arguments_json object, trusted resource or None, normalized destination or None, optional provenance references. Canonical JSON is validated, not an arbitrary free-form string. |
| `AuthorizationDecision` (`schemas.py:97–102`) | UUID decision_id; literal ALLOW/DENY/REQUIRE_APPROVAL; fixed reason_code vocabulary; policy_version; 64-hex request_digest. Unknown fields/effects and invalid model instances reject. |
| `ExecutionResult` (`schemas.py:105–110`) | request_id, optional decision_id, fixed status/reason and JSON tool output. No returned permission/grant that can be fed into execution. |

`request_digest` (`schemas.py:117–121`) hashes canonical JSON containing the fresh request ID, complete principal including tenant/roles/session, normalized tool identity/arguments, trusted resource, destination and optional references. Role sets are sorted explicitly. The decision must match this exact digest and the boundary's expected policy version (`executor.py:94–110`). A replay of an ALLOW for even an otherwise identical proposal fails because the new server request ID differs. The boundary also rejects an ALLOW paired with a non-AUTHORIZED reason.

The digest is a local request binding, not a signature, credential, provenance proof, semantic-equivalence proof or reusable token. It is not written to authorization audit events. If exposed in future logs/transports, hashes permit correlation/dictionary guessing of predictable data and must not be described as anonymization.

## 5. Tool registry implementation

`ToolRegistry` snapshots trusted registrations/resources, rejects duplicate tool keys and ambiguous resource IDs, and resolves an exact `(server_id, tool_name)` tuple (`registry.py:26–47`). `support_registry` explicitly binds these three illustrative tools (`registry.py:50–61`):

| Identity | Schema | Required role | Trusted callable |
|---|---|---|---|
| support / get_order | OrderArguments | support_read | supplied get_order reference |
| support / send_email | EmailArguments | support_email | supplied send_email reference |
| support / issue_refund | RefundArguments | support_refund | supplied issue_refund reference |

Attributes include required role and read/send/refund operation metadata. Unknown identities never trigger arbitrary imports, reflection-based lookup, eval, getattr-based dispatch or shell execution. The resolver returns only a pre-registered trusted callable. The only implemented normalization of tool identity is resolution to its exact registered identity; case variants/aliases are not guessed.

`FakeSupportEnvironment` (`fakes.py:8–37`) contains synthetic order-a/tenant-a and order-b/tenant-b. Each executor records invocation counts and independent argument dictionaries. get_order returns an in-memory order copy; send_email and issue_refund return synthetic outcomes only. There is no real email delivery, customer database, payment, file operation or network call. Resource tenant information comes from the fake environment's trusted catalogue snapshot, not from order IDs asserted as belonging to a tenant by the caller.

## 6. Protected execution flow

```text
untrusted ToolInvocation(server_id, tool_name, arguments)
                      +
trusted application composition
  TrustedContext(principal/session, optional refs)
  ToolRegistry + resource catalogue
  PolicyConfig -> InMemoryPolicy : PolicyDecisionPoint
  AuthorizationAuditSink
                      |
                      v
ProtectedExecutor.execute_authorized
  -> validate typed trusted context
  -> validate ToolInvocation; resolve registered identity
  -> strict tool argument schema -> canonical JSON snapshot
  -> separate frozen execution_arguments (private)
  -> AuthorizationRequest(resource owner, destination, principal)
  -> request_digest
  -> wait_for(policy.evaluate(request)); reject errors/late responses
  -> strict decision validation + digest/version/allow-reason checks
  -> DENY / REQUIRE_APPROVAL -> NOT_EXECUTED audit -> return, zero calls
  -> ALLOW -> required AUTHORIZED audit write
      -> write failure -> ERROR, zero calls
      -> registered executor(private execution_arguments), once
      -> metadata completion/failure event -> structured result
```

Argument schema validation, normalized JSON and the private execution model are built before awaiting policy (`executor.py:69–78`). The PDP sees a separate immutable request representation; dispatch never uses the original mutable invocation dictionary. Tests mutate agent arguments both during evaluation and after the ALLOW decision inside the pre-execution audit callback; the executed order/amount remain the exact authorized snapshot.

`InMemoryPolicy.evaluate` (`policy.py:35–56`) defaults DENY. Rule order: configured policy, known tool, existing trusted resource, tenant equality, required role, tenant-specific email recipient allowlist, refund approval threshold, then ALLOW. Only the threshold is a trusted config value; agents cannot raise it in arguments. Refunds above the threshold return REQUIRE_APPROVAL and do not execute; no approval workflow/bypass exists. Recipient allowlisting is exact normalized synthetic mailbox plus tenant, not a broad domain match. Missing configuration returns DENY under version unconfigured; a boundary expecting v1 also rejects that version mismatch as INVALID_DECISION, still with zero execution.

The async PDP timeout is positive/finite and at most 60 seconds (one second default). Timeout/errors fail closed. An additional elapsed-time check rejects a late ALLOW from cancellation-resistant or event-loop-blocking evaluators (`executor.py:81–93`). Python cannot forcibly stop an indefinitely blocking/cancellation-resistant trusted evaluator in the same process; the check prevents execution if it eventually returns late, but is not a hard real-time process isolation guarantee. Caller cancellation propagates without execution. `_raise_if_cancelled` checks task cancellation at entry, after policy evaluation and immediately before dispatch (`executor.py:15–18`); a policy that suppresses caller cancellation or a cancellation requested during the pre-execution audit cannot turn into an executed tool.

## 7. Security invariants and tests

`tests/test_authorization.py` contains 77 parameterized cases. Important groups:

- Authorized get_order, send_email and issue_refund each execute exactly once, with ordered pre/completion audit events (line 52).
- None, raw dictionaries and validation-bypassed missing principals deny (line 66). Extra identity, tenant, role, session, decision, policy, registry, provenance and classifier fields reject (line 116).
- Wrong roles (including an unrecognized admin role), cross-tenant resources, unknown resources/tools/servers and unauthorized destinations deny, with zero fake calls (lines 82,346).
- Missing arguments, extra authority fields, wrong primitive types, boolean/fractional/negative refunds, recipient header-injection text and blank email bodies reject (line 102).
- Threshold equality can execute; above-threshold refunds require approval and execute zero tools (line 125).
- Missing policy config, timeout/error/None/undefined/extra-field responses, wrong digest/version, model_construct-bypassed decisions and contradictory ALLOW reasons deny (lines 132–162).
- Replay binding tests change arguments, subject, tenant, roles, session, provenance, tool and even nothing except the fresh invocation ID. No saved ALLOW authorizes another invocation (line 183).
- Mutation during evaluation and after ALLOW cannot alter dispatched arguments (lines 165,352). A classifier/agent statement in email text cannot change destination policy (line 204).
- Audit privacy excludes synthetic email body, recipient, argument objects and sensitive exception text from events/stdout/stderr/logs. Unknown tool strings are omitted from audit identity fields (lines 212,314,334).
- Failed mandatory audit writes prevent both allowed and denied dispatch attempts; failed completion audit reports execution already occurred and does not retry (lines 226,234).
- Absent provenance stays None. Twelve concurrent threaded invocations have distinct request IDs, subjects/sessions and correctly bound tenants without shared mutable per-call authorization state (lines 244,254).
- Cooperative cancellation, cancellation-resistant policy and event-loop-blocking late ALLOW cannot dispatch; tool exceptions are sanitized and not retried (lines 269,298,314).
- Caller cancellation suppressed by the evaluator and cancellation immediately after the required audit write both prevent execution (the final two tests). An AUTHORIZED audit event records permission evaluation, not proof that dispatch happened; only an EXECUTED event indicates completion.

Static review checked argument immutability, unknown-field rejection, trusted ownership/role origin, policy version/request binding, audit-before-dispatch ordering, lack of classifier dependencies and absence of new HTTP routes or network/dynamic execution. Constructors and registry/PDP implementations are trusted application code, not remotely selectable agent options.

## 8. Audit event design

Authorization events are separate from the existing text-screening JSONL schema: `event_type=tool_authorization`. `audit.py:9–22` records request/decision IDs, UTC timestamp, trusted subject/tenant, recognized tool identity, effect, fixed reason code, expected policy version, execution status and policy evaluation latency. Rejections before policy evaluation record zero evaluation latency. Completion events keep the same policy latency rather than including tool runtime. No raw email body, recipient address, arguments, classifier/model content, customer financial record, access token/API key or request-binding hash is recorded.

Unknown tools do not contribute agent-controlled identifiers to events. Identity fields are populated only from validated trusted context. Events are frozen; `InMemoryAuditSink.events` returns a tuple snapshot (`audit.py:31–41`). This sink is a local non-durable fixture, not a production append-only store.

Audit behavior is explicit:

- Every ALLOW must successfully record AUTHORIZED before dispatch. Missing/failing sink returns ERROR/AUDIT_UNAVAILABLE and invokes zero tools.
- DENY/approval writes NOT_EXECUTED; sink failure returns ERROR/AUDIT_UNAVAILABLE, still zero tools.
- Successful execution records EXECUTED. If that completion write fails, return EXECUTED_AUDIT_FAILED/AUDIT_UNAVAILABLE; the tool already ran exactly once and is never retried automatically.
- A tool exception attempts a FAILED event and returns ERROR/EXECUTION_FAILED. If that secondary write also fails, the mandatory pre-execution event still exists, but failure-completion detail is unavailable; there is no rollback or retry. This limitation is explicit, not a claim of transactional audit guarantees.

Audit sinks must report errors by raising rather than silently discarding events. The boundary cannot prove durability of a dishonest or misconfigured trusted sink. No existing text audit consumer/schema was altered.

## 9. Test results

Exact commands, from repository root:

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_authorization.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
git diff --check
```

Focused runs passed 65, then 72, then 75 tests as adversarial cases were added; no failures occurred. After the audit-latency correction, 75 passed in 1.22 seconds. The final focused run after caller-cancellation guards: **77 passed / 0 failed / 0 errors / 0 skipped / 0 deselected**, 1.01 seconds. Counts overlap and must not be summed.

Intermediate complete offline runs: **203 passed / 0 failed / 0 errors / 0 skipped / 0 deselected**, 35.16 seconds and then 18.35 seconds after the audit-latency correction. These include the existing 128-test suite plus the then-75 new cases, including existing local checkpoint tests. Final full-source verification after adding the two caller-cancellation cases: **205 passed / 0 failed / 0 errors / 0 skipped / 0 deselected**, 30.20 seconds, exit code 0. This is the final result: 128 existing plus 77 authorization cases. `git diff --check` passed.

The new focused tests ran within the sandbox without temp-path fixtures. Full-suite execution used approved execution outside the sandbox because earlier phases established pytest Windows private-temp-directory access errors under restricted identity. The unchanged existing safe runner clears inherited credentials/overrides, disables dotenv via conftest, blocks real HTTP transports and external connections, enables Hugging Face/transformers offline mode and permits loopback for asyncio's internal socketpair. No dependency installation, download, real provider/API, training or external customer service was used.

No .NET files changed and no cross-language regression was indicated, so the .NET suite was not rerun, as requested. Its historical Phase 1B counts are not presented as new Phase 2A measurements.

## 10. Remaining risks and limitations

- The host must supply genuinely authenticated end-user/session context; typed objects do not authenticate someone by themselves. No HTTP endpoint accepts context, and existing client API keys are not mapped into user claims.
- Same-process trusted registry/PDP/sink/tool references must remain inaccessible to the untrusted agent. Python frozen models/read-only mappings are ordinary application protections, not isolation against arbitrary Python code/private-attribute replacement/object mutation bypasses in the trusted host.
- The catalogue is a trusted local snapshot with globally unique synthetic order IDs. No live ownership lookup, revocation, session expiry, concurrency-safe real database transaction or resource-version revalidation exists. Real implementations need transactional ownership/authorization consistency and idempotency before financial side effects.
- Each allowed call dispatches once locally; repeated separately authorized refund requests are not deduplicated. No distributed exactly-once, crash recovery, rollback or reusable external grant/token mechanism exists.
- Fake email normalization lowercases the entire address for this synthetic allowlist. It is not a general RFC mailbox identity/delivery implementation. No emails or payments actually occur.
- Absent provenance is None/unknown, never public/trusted. Optional references are reserved context fields only. No provenance labels are generated/verified, no source-to-destination taint policy is enforced and no exact paraphrase lineage is claimed. Current permissions depend on roles, resource tenant and destination allowlist, not provenance trust assumptions.
- The in-memory policy is trusted and deterministic. Async timeout cannot preempt arbitrary blocking Python code; late answers deny, but process/service isolation is needed for strong availability guarantees. The sink and fake executor are synchronous trusted calls without preemptive timeouts.
- Required pre-execution audit acceptance prevents unaudited starts in this local design, but completion failure cannot undo an operation. In-memory events are not durable. Trusted subject/tenant identifiers remain sensitive metadata even without argument content.
- The digest is not a signed permission or cryptographic authority boundary. No OPA, real MCP transport, authenticated remote dispatcher, agent framework, external credential isolation or cloud deployment is implemented. The old text-screening and .NET opt-in coverage limits still apply independently.

## 11. Files changed and Git status

Branch: `dotnet-middleware`. HEAD unchanged: `9a139e05fd4d8ed12bc0df2bb06fd171736f4bc6`. Only the seven new `app/authorization/*.py` files, `tests/test_authorization.py` and this report were added in Phase 2A. All remain untracked; nothing was staged. Existing Phase 1A/1B modified/untracked files and the baseline reports were preserved. No existing tracked file was edited by this task.

Commands used for inspection/verification: `Get-Content` of the attached brief, prior reports and existing schemas/gateway/test-runner/conftest/pytest configuration; `rg --files --hidden -g AGENTS.md -g '!venv/**' -g '!.git/**'` (no applicable repository AGENTS.md found); read-only `venv/Scripts/python.exe -B -c` dependency-version probe; focused source reads/`rg -n` for actual function and line references; `git status --short`, `git status --short --untracked-files=all`, `git branch --show-current`, `git rev-parse HEAD` and `git diff --check`. Edits used `apply_patch`. The synthetic terminal demonstration uses only the new in-memory package and prints statuses/call counts, never raw arguments/customer records. No Git mutations or identity/GitHub settings changes occurred.

## 12. Recommended next implementation step

Architecture review should approve the trust/argument/binding/audit contracts before adding a transport. The next scoped design should specify a trusted identity/session adapter, authenticated transport and sole credential-holding dispatcher; then map actual MCP operations into this boundary with explicit unsupported-operation rejection. Select an OPA policy adapter and stronger resource/audit consistency only as separately approved milestones. Stop after Phase 2A; no such integration is implemented here.
