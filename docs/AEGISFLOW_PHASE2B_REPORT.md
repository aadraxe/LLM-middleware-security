# AegisFlow Phase 2B report

## 1. Architecture and trust boundaries

Implemented an isolated official-SDK MCP server adapter, preserving Phase 2A. Initial branch was `dotnet-middleware`, working tree clean, HEAD `f5baf1b116526ebd840aede692fb0498196bcbad`. The Phase 1A (`6bf74e5`), 1B (`ef08ea9`) and 2A (`f5baf1b`) commits were verified before editing. Prior reports, authorization package and existing tests were inspected. No existing gateway, classifier, RAG, authorization, .NET, model, dataset or benchmark implementation was changed.

```text
Trusted local harness (not an MCP argument or public endpoint)
  -> synthetic environment + trusted registry/resource catalogue
  -> InMemoryPolicy + AuthorizationAuditSink -> ProtectedExecutor
  -> typed TrustedContext per local principal/session
  -> create_local_protected_server(executor, trusted_context)

Official SDK Client(server, mode="legacy", cache=None)
  -> native memory transport + JSONRPCDispatcher
  -> initialize / notifications/initialized (MCP 2025-11-25)
  -> tools/list -> exactly three explicit schemas
  -> tools/call -> SDK Server.on_call_tool
      -> exact public tool allowlist
      -> ToolInvocation(server_id="support", name, arguments)
      -> ProtectedExecutor.execute_authorized(proposal, local_context)
          -> strict arguments/snapshot, trusted tenant/role/destination policy
          -> exact decision binding/version + required audit before dispatch
          -> registered fake tool only on ALLOW
      -> native CallToolResult (structured content, text content, is_error)
```

The alternative SDK modern in-process path is also tested against allow and deny, but the principal protocol tests deliberately use legacy mode: SDK auto mode would use direct dispatch without the initialization handshake/JSON-RPC streams. No JSON-RPC parser or homegrown transport was implemented. Result text JSON serialization is just content formatting inside a native CallToolResult.

## 2. SDK version and installation status

Selected and installed **`mcp==2.3.0`**, the official stable release, with matching `mcp-types==2.3.0`. Selection used the [official release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0), [tagged dependency metadata](https://github.com/modelcontextprotocol/python-sdk/blob/v2.3.0/pyproject.toml), [official testing guidance](https://py.sdk.modelcontextprotocol.io/get-started/testing/) and [low-level Server guidance](https://py.sdk.modelcontextprotocol.io/advanced/low-level-server/). Python 3.13.9 satisfies that release's requirements. Installed API signatures and source were inspected, rather than assuming v1 FastMCP/ClientSession decorator examples apply to v2.

The supervisor explicitly authorized installation after the task initially stopped on the absent SDK. Before installation, all installed distribution versions were captured in ignored `.test-tmp/mcp-existing-constraints.txt`. Exact installation command:

```powershell
& venv/Scripts/python.exe -m pip install 'mcp==2.3.0' --constraint .test-tmp/mcp-existing-constraints.txt --disable-pip-version-check
```

Result: SDK and missing required dependencies installed; **zero pre-existing distribution versions changed**, verified against that snapshot after installation. New distributions:

```text
mcp==2.3.0, mcp-types==2.3.0, jsonschema==4.26.0,
jsonschema-specifications==2025.9.1, referencing==0.37.0,
rpds-py==2026.9.1, opentelemetry-api==1.45.2,
PyJWT==2.15.1, cryptography==50.0.2, cffi==2.1.1,
pycparser==3.12, python-multipart==0.0.33, pywin32==312,
sse-starlette==3.6.0
```

Existing Pydantic 2.13.4, AnyIO 4.13.0, httpx2 2.16.0, Starlette 1.2.1 and uvicorn 0.49.0 were retained. `requirements-mcp.txt` pins the optional SDK separately; base/classifier requirements were not changed. The ignored constraint snapshot is a local installation safeguard, not a committed portable lockfile. Transitive dependencies are listed here as observed, not claimed fully locked for future environments.

`pip check --disable-pip-version-check` returned one **pre-existing** incompatibility: datasets 5.0.0 requires huggingface-hub <2.0, while 2.4.0 was already installed. Both versions were confirmed in the before-install snapshot, and neither changed. No MCP dependency conflict was reported. This unrelated environment warning was not repaired by upgrading/downgrading existing packages. The required full regression suite passes; this report does not claim a globally clean pip-check result.

## 3. MCP tools implemented

The public surface in `app/mcp/server.py:17–21` contains only:

| MCP name | Runtime argument schema | Registered Phase 2A identity |
|---|---|---|
| get_order | OrderArguments: order_id | support / get_order |
| send_email | EmailArguments: order_id, recipient, body | support / send_email |
| issue_refund | RefundArguments: order_id, amount_cents | support / issue_refund |

Discovery generates fresh SDK Tool objects with JSON schemas from the existing Phase 2A models (`server.py:46–49`). Schemas forbid additional properties; no principal, role, tenant, permission, policy or decision parameter is advertised or accepted as authority. Registered executor references are never exposed as tools. `get_customer_record`, `search_knowledge_base`, arbitrary Python execution and policy mutation are not implemented.

The adapter's fixed allowlist is independent of the trusted registry: even a separately registered hidden tool is not callable through this public server. Tests verify this explicitly. Stable identities are exact-case; aliases/prefixes/trailing whitespace do not bypass the public surface.

## 4. Protocol/transport implementation

`app/mcp/server.py` uses official `mcp.server.Server`, ServerRequestContext and native tool request/result classes. Only on_list_tools and on_call_tool callbacks are installed (`server.py:70–71`). SDK protocol plumbing handles initialization, notifications, discovery and invocation. Legacy memory tests verify `Client.session.initialize_result`, negotiated protocol and server capabilities before issuing calls (`tests/test_mcp.py:55–76`).

No listener, module-level ASGI application, HTTP route, subprocess server command or stdio launcher is added. Scope is the native in-memory SDK transport with real handshake-era messages, plus a focused modern in-process adapter-path check. This is MCP-compatible server behavior exercised through the SDK, not network deployment or HTTP/OAuth verification. Resources/prompts are not advertised; sampling, elicitation, subscriptions, remote transports and comprehensive provider/transport support are not claimed.

The low-level SDK advertises input schemas but does not perform tool argument validation automatically. Therefore runtime validation remains mandatory in ProtectedExecutor, never inferred from tools/list. Invalid/missing/extra arguments return a native error result with fixed reason codes. Unknown public names reject at the adapter without attempting protected execution.

## 5. Identity handling

`create_local_protected_server` accepts only a TrustedContext instance or None, revalidates it, and captures a private immutable binding (`server.py:35–44`). A raw agent-shaped identity dictionary raises a fixed TypeError during trusted composition. None deliberately causes MISSING_CONTEXT denial on every known tool call.

No identity is read from MCP arguments, clientInfo, request `_meta`, headers, role strings in message content or a shared API key. A separate binding is created by trusted harness code for each distinct local principal/session; no global identity or ContextVar inheritance is used. Multiple concurrent clients on a particular binding share that binding's explicitly configured principal; this is intentional for a local harness, not per-user authentication.

**This is not production authentication.** In-memory transport has no HTTP credential validation; SDK HTTP/OAuth authentication does not apply to this harness. A future Streamable HTTP design must verify credentials, issuer/audience/expiry and relevant session properties; derive subject, tenant, roles and permissions only from verified claims/server records; and bind those attributes to the actual request/session. Do not publicly host this fixed-context factory as an authenticated multi-user service. No agent-supplied principal-selection endpoint exists.

## 6. Authorization integration

The single SDK tools/call callback handles the explicit three-tool surface (`server.py:51–68`):

1. Reject non-public names with UNKNOWN_TOOL.
2. Construct ToolInvocation with fixed trusted server ID support and SDK-provided name/arguments.
3. Delegate to `executor.execute_authorized(proposal, local_context)` once.
4. Return output only for EXECUTED; DENIED, APPROVAL_REQUIRED and errors set is_error=True and omit output.

No handler imports or calls a fake implementation, copies role/tenant/destination policy rules, accepts an external decision/token, or changes Phase 2A invariants. Registry resolution, immutable argument snapshot, resource ownership, role/recipient/refund checks, decision digest/version checks, cancellation handling and pre-execution audit remain Phase 2A responsibilities. No classifier result enters this path.

Results contain a fixed status/reason_code and, only on execution, JSON tool output (`server.py:24–32`). Unexpected adapter/boundary exceptions become ERROR/AUTHORIZATION_UNAVAILABLE; exception text, Pydantic input values and request arguments are not interpolated. CancelledError propagates, with no unguarded retry. Unknown public names and malformed protocol envelopes rejected before Phase 2A do not produce authorization audit events; normal known-tool decisions use the existing separate AuthorizationAuditSink. The adapter introduces no raw-argument logs.

Existing post-execution audit semantics are preserved: EXECUTED_AUDIT_FAILED reports an error but the tool has already run; clients must not infer zero side effects or automatically retry that status. The required pre-execution audit failure is tested over MCP and causes zero fake calls. No new transactional guarantee is claimed.

## 7. Security tests and results

Exact final verification commands:

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_mcp.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_authorization.py -q -p no:cacheprovider --tb=short
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
git diff --check
```

| Verification | Actual final result |
|---|---|
| MCP integration tests | **49 passed / 0 failed / 0 skipped**, 2.16 seconds |
| Existing Phase 2A authorization tests | **77 passed / 0 failed / 0 skipped**, 1.09 seconds |
| Full offline Python suite | **254 passed / 0 failed / 0 errors / 0 skipped / 0 deselected**, 22.24 seconds |
| Whitespace review | git diff --check passed; new-file syntax/whitespace checked before staging |

Counts overlap; the full suite is the prior 205 plus 49 MCP cases. .NET was not modified or rerun. No live LLM, real email/payment/customer database or AWS service was called. Approved package retrieval was the only new dependency-installation network work; documentation and Git remote checks are separate from offline tests.

Tests cover initialization and exactly three discovered schemas; each tool's single authorized execution; wrong roles/cross-tenant/unknown-resource/unapproved-recipient/approval-required/missing-context denials; alias and excluded-tool rejection; strict primitive types and required/extra fields; forged authority in arguments and `_meta`; timeout/exception/undefined/replayed policy responses; pre-execution audit failure; sanitized exception/result formats; privacy including DEBUG-captured application/SDK diagnostics on the tested path; and concurrent isolation of two trusted bindings sharing the same executor. A hidden trusted registry tool cannot be reached through the public MCP interface. Repeated calls generate distinct authorization request/decision IDs. Client cancellation executes no tool. A modern in-process SDK path also denies insufficient roles, preventing a transport-dispatch shortcut around the callback.

Intermediate MCP run: 45 passed / 1 failed because the test incorrectly treated SDK v2 RequestParamsMeta as a Pydantic model. Installed source showed a TypedDict; the test was corrected to send native typed metadata. The subsequent combined MCP/authorization run passed 123 tests (46 +77), and an intermediate full run passed 251 in 20.82 seconds. Adding repeated-call, modern-path and cancellation tests produced the final 49/254 counts. No unresolved test failures or disabled tests remain.

Full regression execution used the same approved outside-sandbox context as earlier phases to avoid Windows pytest temporary-directory permission errors. The existing offline runner was not modified; it blocks real HTTP transports/external connects and model downloads, while permitting asyncio loopback setup. New MCP tests ran inside the sandbox successfully. The complete new source/diff was reviewed before staging.

Executed demonstrations, using actual SDK Client with mode legacy and synthetic fixture composition:

```text
MCP handshake protocol: 2025-11-25
A. Authorized MCP get_order: EXECUTED underlying calls: 1
B. Unauthorized MCP get_order: DENIED WRONG_ROLE underlying calls: 0
```

The two calls use the same tool name/arguments with separately bound local principals having sufficient versus empty roles. Denied execution count is the observed additional count, not a fabricated response-only assertion. Tests additionally verify the tool argument recorder stays empty on denied operations.

## 8. Bypass limitations

- Every supported tools/call exposed by this adapter enters ProtectedExecutor before dispatch; tool discovery never grants access. Unknown public names reject before resolving any underlying callable. No alias, hidden registration, argument field or metadata identity bypass was found in the tested interface.
- Trusted host code still possesses FakeSupportEnvironment methods and registry entries and can call them directly. An agent given arbitrary Python execution, private host object access or ability to replace handlers/policy can bypass an application boundary. No sandbox against malicious same-process Python is claimed.
- Context originates only in trusted local composition. No HTTP/OAuth token, remote-session binding, credential isolation or real identity issuer is implemented. An incorrectly deployed fixed privileged binding would expose its privileges to all clients; it must remain local-test-only.
- Only the documented tools and in-memory protocol paths were tested. The SDK supports other transports, but this milestone does not claim those are secured or production-ready. Prompts, resources, sampling and elicitation have no protected implementations here.
- Existing Phase 2A limits remain: static resource snapshot, no session expiry/revocation, no financial idempotency/distributed transactions, non-durable in-memory audit and cooperative same-process policy cancellation. Completion failures cannot undo operations. Real deployments need sole credential-holding dispatch plus network/process isolation to prevent alternate executor access.
- The existing datasets/huggingface-hub pip-check conflict remains an unrelated environment warning; all original versions were preserved and required regressions passed. No claim of a fully resolved global dependency graph is made.

## 9. Files changed

New:

```text
app/mcp/__init__.py
app/mcp/server.py
requirements-mcp.txt
tests/test_mcp.py
docs/AEGISFLOW_PHASE2B_REPORT.md
```

Modified: `README.md` only, to document the optional SDK, local composition, protected tools and authentication limits. Existing authorization code/tests, FastAPI routes/authentication, .NET, RAG, models, data and evaluation files were not edited. The installation changed only the ignored virtual environment and created an ignored constraint snapshot.

Read-only inspection included Git status/log/branch, prior reports/source/test runner, installed SDK signatures/source and distribution metadata, official documentation, pip check, dependency-version comparisons and the synthetic SDK demonstration. `git ls-remote --heads origin refs/heads/dotnet-middleware` verified the remote branch at the pre-existing local checkpoint before commit; the expected origin is the existing aadraxe/LLM-middleware-security GitHub repository. No Git identity configuration changes are made. Staging is restricted to the six Phase 2B files above, after tests, secret/generated-artifact review and author/committer checks.

This report is authored before its commit. Requested exact commit subject: `feat(mcp): enforce authorization on protected tool calls`. The resulting commit hash and verified remote branch are reported in terminal/final output after normal push. No main merge, pull request, force-push or history rewrite is part of this task. If remote divergence/authentication or acceptance failure occurs, commit/push stops and the blocker is reported.

## 10. Recommended next step

Architecture review should assess the protocol adapter, per-binding local context and exact dispatcher/audit behavior. Before external serving, design and test a trusted credential-to-context adapter with per-session isolation and a credential-holding executor unreachable through alternate paths. OPA and provenance remain separate future phases. Stop after Phase 2B; no extra tools, cloud deployment or unrelated changes are included.
