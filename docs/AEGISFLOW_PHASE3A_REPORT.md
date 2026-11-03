# AegisFlow Phase 3A report

## 1. Executive summary

Implemented trusted source metadata and conservative session exposure tracking for the existing three synthetic MCP tools. A provenance-enabled ProtectedExecutor preserves the Phase 2A invocation policy, then independently checks information-flow policy immediately before email dispatch. An ordinary role/destination ALLOW cannot override a flow DENY. An authorized get_order labels its result CONFIDENTIAL/TRUSTED before releasing output. Unknown or unavailable required exposure prevents outbound email.

Initial working tree was clean on dotnet-middleware at 375be135a3173a3adb4ca1cfd34fc656d50cd625. The previous checkpoint and prior phase commits were present. Phase 2A/2B reports, actual authorization/MCP implementations and their tests were inspected before implementation. Final verification: **24 provenance tests, 36 new MCP flow tests, 126 existing authorization/MCP tests and 314 full-suite tests passed**. Counts overlap. No tests failed or were disabled.

No dependencies were installed or changed. No classifier/model configuration, gateway, .NET, dataset, benchmark, RAG or prior report was changed. No production authentication, OPA, remote server, cloud access, real email/payment or customer-data processing was introduced. Git identity is preserved; the requested normal commit/push is performed only after verification, with resulting identifiers reported in terminal/final output.

## 2. Architecture diagram

```text
Trusted local harness
  -> typed principal/session (outside MCP tool payload)
  -> shared ArtifactStore; explicitly register fresh clean or UNKNOWN session
  -> exact destination sensitivity configuration -> FlowPolicy
  -> ProvenanceGuard(store, flow policy, metadata-only flow audit)
  -> ProtectedExecutor(existing registry, invocation policy, authorization audit,
                       flow_guard=guard)
  -> existing local MCP server binding / official SDK memory transport
      tools/call
        -> strict invocation/context validation
        -> shared tenant/session serialization lock
        -> existing argument snapshot + request-bound invocation authorization
        -> mandatory existing authorization audit acceptance
        -> synchronous store transaction (no await)
             send_email: resolve current exposure + flow policy + required flow audit
                         recheck exposure after audit, then dispatch exact snapshot
             get_order: registered fake dispatch -> confidential artifact/exposure
                        -> required exposure audit -> output plus artifact reference
             issue_refund: existing threshold/approval behavior
        -> existing execution completion audit / release locks
```

Source-level provenance records a trusted producer/resource relationship. Session-level exposure conservatively restricts subsequent email regardless of its body. **Exact content-level, token-level or semantic/paraphrase lineage is not implemented.** No inference from classifier cleanliness or LLM claims occurs.

## 3. Provenance model

app/provenance/models.py defines frozen, extra-forbidden, strict, instance-revalidated models, reusing Phase 2A identifiers. DataArtifact contains a server-generated UUID, controlled TOOL_RESULT/DERIVED source kind, resource ID, registered support/get_order producer identity, tenant/session, PUBLIC/INTERNAL/CONFIDENTIAL/UNKNOWN sensitivity, independent TRUSTED/UNTRUSTED/UNKNOWN trust, immutable parent UUID tuple, UTC timestamp and optional canonical-content SHA-256.

Classification and trust are distinct: tests include PUBLIC/UNTRUSTED and CONFIDENTIAL/TRUSTED artifacts. The store retains metadata and digests, not order dictionaries or email bodies. Digests are correlations of known canonical content, not semantic provenance, anonymous identifiers or permissions. Artifact IDs are references only.

Exposure binds tenant/session and subject, effective sensitivity, immutable artifact IDs and a monotonic revision. UNKNOWN dominates the sensitivity join: learning confidential data does not erase earlier uncertainty. Otherwise the highest sensitivity is retained. Absent provenance never becomes PUBLIC automatically.

## 4. Trusted source-labeling mechanism

The existing registry supplies verified resource ownership and callable identity to the executor. After a successful support/get_order return, ProvenanceGuard calls the trusted store with that request's principal/resource and known returned content. The guard fixes CONFIDENTIAL/TRUSTED labels; no tool argument selects these attributes. A reference is exposed only after successful metadata and required exposure audit acceptance.

ArtifactStore.record_order is an internal trusted application interface, not an MCP tool or import/deserialization endpoint. It issues IDs itself, checks resource tenant, resolves parents within the same tenant/session, rejects sensitivity downgrade and rejects upgrading untrusted/unknown parent trust to TRUSTED. It supports trusted derived-artifact tests but provides no update, deletion, relabeling or declassification API. New nodes can reference only existing nodes; immutable append-only insertion prevents creating cycles through this interface. Lineage traversal additionally detects cycles/missing references in corrupted records and returns a deduplicated parent-first tuple.

Duplicate UUID generation rejects without overwriting. Forged model construction does not register an artifact. Test code intentionally accesses private dictionaries to simulate corruption; these dictionaries must remain inaccessible to agents. Frozen models and private attributes are application protections, not a sandbox against malicious Python.

Denied or failed tool retrievals create no success artifact. If a fake retrieval ran but tracking/audit failed, the result is withheld and the session is permanently poisoned in this store. Subsequent email fails closed. The retrieval may have executed once; the failure event therefore says FAILED, not NOT_EXECUTED. No rollback or automatic retry is claimed.

## 5. Session exposure tracking

Trusted harness code explicitly registers a fresh session. The default is UNKNOWN. Only known_clean=True, a strict boolean assertion by the harness, initializes a known-empty PUBLIC exposure state. This attests absence of known sensitive inputs in the controlled experiment; it does not establish that arbitrary real-world sessions are safe. Re-registering/resetting an existing session fails. No agent-facing context-selection or session-reset endpoint exists.

Tenant/session keys isolate state, and subject binding prevents assigning the same key to another subject. Session state reads revalidate models, artifact bindings, complete artifact index, revision and lineage. Missing, mismatched, malformed or poisoned state cannot authorize email. Optional context provenance references are also resolved against the active tenant/session; references cannot grant access or weaken the conservative session exposure.

Successful confidential retrieval raises exposure before its result leaves the executor. A session is never implicitly cleaned after errors or between calls. Trusted session IDs must be unique and stable for the intended agent execution; giving the agent authority to create fresh trusted clean sessions would defeat this experiment.

## 6. Information-flow policy

The existing async InMemoryPolicy remains unchanged: it still checks registered identity, resource, tenant, role, exact recipient allowlist and refund threshold. A small typed ExecutionFlowGuard extension adds a separate mandatory check for configured executors. Defaults preserve existing Phase 2A callers without the extension; the README shows explicit provenance-enabled composition. Every executor/binding serving a protected experimental session must share this store/guard contract. The MCP payload cannot opt out.

FlowPolicy uses trusted exact (tenant, normalized mailbox) configuration mapped to permitted sensitivities. It never infers trust from domain suffixes or model descriptions. UNKNOWN always denies, including if listed in configuration. Missing destination configuration denies. The experiment permits PUBLIC/INTERNAL to the already-approved synthetic mailbox and prohibits CONFIDENTIAL. A trusted configuration can explicitly permit confidential flow to that exact destination; it still cannot override ordinary recipient/role denial.

No approval or declassification mechanism is introduced. Flow denial is FLOW_DENIED; malformed/unavailable state, flow-policy exceptions, undefined/non-boolean answers, required flow-audit failures or late policy results are PROVENANCE_UNAVAILABLE. Both prevent email execution. The deterministic flow evaluator is synchronous and local; elapsed-time validation rejects a late answer, but cannot preempt indefinitely blocking trusted code. Existing async invocation-policy deadlines/cancellation behavior remains intact. The default flow deadline is one second, finite/positive and capped at 60 seconds.

## 7. MCP integration changes

The official SDK server and its three schemas/handlers remain unchanged: each calls ProtectedExecutor. No handler calls a fake tool or trusts identity, classification, artifact IDs or source labels in tool arguments. Existing extra-field rejection applies to forged metadata. The new integration tests run native Client(mode="legacy", cache=None) over SDK memory transport and the existing local trusted binding.

The smallest security-sensitive change is an optional trusted ExecutionFlowGuard protocol/constructor parameter in ProtectedExecutor plus two fixed failure reason codes. It enables serialization before policy evaluation and a final flow check inside the sole dispatch boundary, using the already-validated immutable request/argument snapshot. No duplicate role/tenant implementation or external grant is added. Direct execute_authorized calls on a configured boundary receive the same protection as MCP calls.

Only provenance-enabled get_order output changes: output now contains data and artifact_id. Non-enabled executors retain the prior raw output shape. Email/refund successful outputs and existing public MCP tool arguments remain unchanged. Local typed identity remains test-only; no HTTP/OAuth or production identity claim is made.

## 8. Concurrency and consistency guarantees

Each shared store owns a thread-safe lock table keyed by tenant/session. The guard acquires that session lock before invocation authorization and retains it through dispatch, retrieval metadata update and completion handling. It uses nonblocking threading.Lock acquisition with cooperative asyncio yielding, allowing different event loops/threads to coordinate without blocking an event loop while waiting. Cancellation while waiting acquires no lock; finally releases any owned lock. No per-session global module state exists.

A separate store RLock protects every metadata operation. The final synchronous flow-check/dispatch/registration section holds it with no awaits, excluding concurrent trusted metadata writes across threads. Therefore a write either precedes the final check and is observed, or follows dispatch. Required audit callbacks execute before dispatch; exposure is rechecked after the flow audit to reject synchronous reentrant changes. Ordinary pre-dispatch audit callbacks that introduce exposure are also observed by the final check.

Deterministic tests hold retrieval at an async policy barrier, observe the same-session email attempting the session lock, verify its policy has not started, and allow a different clean session to send before releasing retrieval. The queued email then sees confidential exposure and denies. Another test starts a separate metadata-writer thread during final flow evaluation: it cannot complete until dispatch finishes; the following email then denies. No timing sleeps establish these properties. Mutation of the original invocation during policy evaluation cannot alter dispatched arguments.

Guarantees are local to cooperating trusted code sharing this store and configured executors. Locks are not distributed transactions, process isolation, crash recovery or financial idempotency. The brief final synchronous section serializes different sessions' fake dispatches too; slow/reentrant real tools would require a reviewed asynchronous/transactional design. The lock table/store/audit fixture are unbounded and non-persistent, with no session expiry/eviction or restart recovery.

AuthorizationAuditEvent remains unchanged except the additional reason vocabulary. Complementary FlowAuditEvent records request ID, registered tool, tenant/session, relevant artifact UUIDs, effective sensitivity, flow policy version, fixed decision/reason/status and UTC timestamp. It excludes raw arguments, destinations, returned orders and email bodies. Both sinks must accept required pre-execution events. AUTHORIZED records permission evaluation, not execution success; the existing EXECUTED completion event reports completion. EXPOSURE_RECORDED reports registered exposure, not an email dispatch. If a flow denial/unavailable audit write also fails, execution still does not occur and the authorization sink records the rejection when available. All-sink failure cannot guarantee audit durability.

## 9. Test results

Exact final-source commands from repository root:

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_provenance.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_mcp_flow.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_authorization.py tests/test_mcp.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
git diff --check
```

| Verification | Actual result |
|---|---|
| New provenance unit tests | 24 passed, 0 failed/skipped, 1.61 seconds |
| New MCP flow integration tests | 36 passed, 0 failed/skipped, 2.02 seconds |
| Existing authorization + MCP tests | 126 passed, 0 failed/skipped, 2.71 seconds (77 + 49 existing cases) |
| Full offline Python suite | 314 passed, 0 failed/errors/skipped/deselected, 84.97 seconds, exit 0 |
| Whitespace check | PASS |

Intermediate combined runs passed 176 and then 186 cases as concurrency/error tests were added. The new-only combined run passed 60 in 3.11 seconds. There were no failed/interrupted test runs in this phase. Counts overlap and must not be added. The full suite includes the existing local checkpoint tests, not new efficacy/benchmark measurements. No .NET tests ran because no .NET files changed.

New tests cover strict frozen metadata/UTC/labels, forged/missing IDs, wrong tenant/session, invalid parents, duplicate IDs, downgrade/trust-upgrade rejection, cycle/corruption detection, 32 concurrent metadata writes, unknown/poisoned states, source-label injection, denied/failed retrievals, ordinary and flow policy failure/late answers, audit/store failures, precise original-argument binding, refund threshold preservation, explicit trusted confidential destination permission, flow audit privacy, and lock/cancellation/isolation consistency. Existing cases exercise original policy denials and request binding.

Full-suite execution used approved outside-sandbox execution for the known Windows pytest private-temp-directory limitation. The unchanged offline runner blocks real HTTP/external connections and model downloads, disables inherited credentials/overrides and permits asyncio loopback setup. Focused tests ran successfully in the restricted context. No packages, external models or services were fetched. Git remote operations are separately authorized, not application network behavior.

## 10. Demonstrations A-E

Actual terminal demonstration used synthetic fixtures and the native SDK client. Relevant results:

```text
A. Ordinary role/destination + clean flow: EXECUTED email calls: 1
B. Prohibited destination: DESTINATION_DENIED additional email calls: 0
C. Confidential retrieval: EXECUTED artifact returned: True
C. Ordinary policy for same email: ALLOW
C. Combined flow result: FLOW_DENIED additional email calls: 0
D. Isolated clean session: EXECUTED additional email calls: 1
E. Missing provenance: PROVENANCE_UNAVAILABLE additional email calls: 0
```

Scenario C uses the exact same email recipient/body as A. Its separate ordinary policy evaluation returns ALLOW; the combined executor still refuses dispatch. Counts are actual fake-counter differences, not response-only assertions. Scenario E tests additionally cover UNKNOWN, corrupted/unavailable state and forged references. The integration test repeats three deliberately harmless greetings after retrieval: **3/3 are blocked with zero additional email calls**, measuring conservative overblocking in this synthetic fixture, not a population false-positive rate.

## 11. Known limitations and potential false positives

- Source metadata describes a trusted fake producer/resource, not proof of semantic dependence of arbitrary generated text. No LLM self-report, embeddings, classifier or digest can precisely attribute paraphrases here.
- Session exposure intentionally overblocks harmless email after retrieval. It can also miss real-world sensitive inputs not mediated/labeled by this experimental boundary; UNKNOWN must remain unknown for such sessions. Known-clean registration requires honest trusted harness lifecycle management.
- Configuring an unguarded executor or an independent store for the same protected session bypasses this optional experiment. All relevant execution paths must use the configured common boundary. Arbitrary Python access to tools, policies or private store state is outside the application threat boundary.
- In-memory stores/audits are non-durable and have no distributed locks, resource revocation, session expiry, financial exactly-once behavior, data retention system or production authentication. Session/artifact identifiers and digests remain sensitive metadata.
- Sync policy, audit and fake tool calls cannot be forcibly preempted. The flow timeout rejects late results after return; availability isolation is not claimed. A post-execution audit failure cannot undo a completed operation and must not prompt blind client retries.
- No automatic declassification, new tools, network transport, RAG labeling, OPA, production customer integration, model training, cloud or dashboard is implemented. The previously documented dependency-environment warning is unaffected; no package change occurred.

## 12. Files changed

New:

```text
app/provenance/__init__.py
app/provenance/models.py
app/provenance/store.py
app/provenance/flow_policy.py
app/provenance/tracker.py
tests/test_provenance.py
tests/test_mcp_flow.py
docs/AEGISFLOW_PHASE3A_REPORT.md
```

Modified: app/authorization/executor.py (optional typed flow extension and local transaction), app/authorization/schemas.py (two fixed reason codes), README.md (explicit trusted composition and behavior). Existing policy, registry, tool schemas/fakes, MCP handlers, tests and prior reports are preserved. No generated artifacts are intended for staging.

Inspection/verification used the attached brief, source/report/test reads, focused rg/file searches, read-only Git status/log/branch/diff checks, identity comparison without printing email, offline tests and synthetic demonstrations. The initial repository instruction-file search found no applicable AGENTS.md. No Git identity/configuration mutation occurred. Git commit/push verification follows this report's preparation; exact requested subject is feat(provenance): enforce session-aware information flow. Only these eleven Phase 3A files are staged. No main merge, PR, force-push or history rewrite is authorized/performed.

## 13. Recommended next step

Architecture review should assess optional-boundary composition, clean-session attestation, conservative false positives and local transaction/audit semantics before selecting the next phase. Before real services, design trusted session issuance, complete input mediation, durable consistency and a sole credential-holding executor with alternate paths prevented. Stop after Phase 3A; no further integration begins here.
