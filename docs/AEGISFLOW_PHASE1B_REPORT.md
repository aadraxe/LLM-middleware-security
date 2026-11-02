# AegisFlow Phase 1B report

## 1. Executive Summary

Phase 1B hardens the existing .NET text-screening integration for AF-03 and AF-04. `LlmGuardOptions.FailMode` and the sample now default to `FailClosed`. Configured protected requests stop when the gateway is unavailable or required content cannot be inspected. Explicit `FailOpen` remains a documented legacy opt-in, with warnings; it never overrides a content block, caller cancellation, oversize rejection or stream-read failure.

Fresh-source Release rebuild: **PASS, zero warnings/errors**. Final freshly built xUnit suite: **104 passed, 0 failed, 0 skipped**. Focused new hardening cases: **43 passed, 0 failed, 0 skipped**, overlapping the full suite. Existing offline Python suite: **128 passed, 0 failed, 0 skipped, 0 deselected**. No SDK/package installations, restore/downloads, live services, model downloads, training or AWS access were performed.

Read the baseline and Phase 1A reports before implementation. Existing Phase 1A changes were preserved. No Python source/tests/configuration, model checkpoints, datasets, benchmark code/results or prior reports were modified by this task. No MCP, OPA, provenance, tool-execution authorization or unrelated features were implemented. No commits, pushes, history changes or Git identity/configuration changes occurred.

## 2. Root Causes

Before Phase 1B, `FailOpen` was the options default and sample configuration; gateway failures became `GuardOutcome.FailedOpen`, whose `IsAllowed` is true. Incoming middleware continued on missing/non-string/empty prompt or invalid JSON. Outgoing extraction ignored unsupported messages/parts and forwarded when no text was extracted. Thus extraction failures bypassed even explicit `FailClosed`, because no gateway failure decision was produced.

The baseline test result came from an old assembly. Sample integration tests also inherited the host's Windows Event Log provider, causing permission-dependent failures. This task rebuilt current source using existing restored dependencies and removed only the machine logging sink from the in-memory test host (`dotnet/tests/LlmGuard.Tests/ChatApiIntegrationTests.cs:24–35`). Application screening and fake downstream assertions remain enabled. No Windows permissions or production logging providers were changed.

## 3. Files Modified

Paths below are relative to the repository root. All line references in this report refer to the Phase 1B working tree.

| File | Purpose |
|---|---|
| `dotnet/src/LlmGuard/LlmGuardOptions.cs` | Safe default, legacy opt-in XML documentation, incoming/outgoing body-limit contract. |
| `dotnet/src/LlmGuard/LlmGuardClient.cs` | Pre-cancellation check; sanitized response-read failure; fixed-vocabulary layer and finite/nonnegative required latency validation. |
| `dotnet/src/LlmGuard/LlmGuardMiddleware.cs` | Explicit format failures, bounded body read, safe failure codes, default-closed extraction, cancellation before downstream execution. |
| `dotnet/src/LlmGuard/LlmGuardHandler.cs` | Options-aware overload, protected method scope, bounded outgoing buffering, strict whole-payload extraction and safe unavailable outcomes. |
| `dotnet/src/LlmGuard/PayloadInspection.cs` (new) | Internal inspection outcomes, JSON media-type/charset checks, duplicate-property detection and bounded stream reader. |
| `dotnet/src/LlmGuard/GuardDecision.cs` | Update unavailable-exception documentation for unconditional size/read rejection. Public outcomes and exception constructors retained. |
| `dotnet/src/LlmGuard/LlmGuardExtensions.cs` | Reject undefined failure-mode enum configuration at startup. |
| `dotnet/src/LlmGuard/Log.cs` | Metadata-only warning event for inspection failures and explicit legacy forwarding. |
| `dotnet/samples/ChatApi/appsettings.json` | Explicit FailClosed sample configuration. |
| `dotnet/tests/LlmGuard.Tests/HardeningTests.cs` (new) | Boundary, schema, failure, stream, cancellation, privacy and legacy coverage. |
| `dotnet/tests/LlmGuard.Tests/LlmGuardClientTests.cs` | Add gateway 403; default-closed warning expectation. |
| `dotnet/tests/LlmGuard.Tests/LlmGuardMiddlewareTests.cs` | Replace unsafe pass-through expectations with rejection/zero execution; make legacy outage choice explicit; share in-memory host setup internally. |
| `dotnet/tests/LlmGuard.Tests/LlmGuardHandlerTests.cs` | Default-closed setup; unsupported formats reject; preserve text-array/tool-result coverage and existing concurrency/block tests. |
| `dotnet/tests/LlmGuard.Tests/ChatApiIntegrationTests.cs` | In-memory logging isolation, explicit legacy test, verify actual sample FailClosed configuration. |
| `dotnet/tests/LlmGuard.Tests/TestDoubles.cs` | Safe default in synthetic option fixtures. |
| `dotnet/README.md` | New behavior, migration, precise schemas/method scope, limits and text-screening versus authorization distinction. |
| `docs/AEGISFLOW_PHASE1B_REPORT.md` (new) | This report. |

`dotnet/samples/ChatApi/Program.cs`, solution/project files and dependency references were inspected but did not need changes. Existing named `llm` client already installs `AddLlmGuardHandler` at line 33; incoming middleware is installed at line 41 before `/chat` execution. Generated ignored `bin/obj` outputs were rebuilt; no dependency manifests were edited.

## 4. Failure-Mode Changes

`LlmGuardOptions.cs:43` initializes `FailClosed`; enum numeric values remain unchanged for API compatibility. `LlmGuardExtensions.cs:106–109` rejects unknown enum settings. No new environment-based bypass exists: the existing operator-controlled configuration binding is retained, and legacy forwarding requires an explicit valid FailOpen value.

`LlmGuardClient.CheckAsync` (`LlmGuardClient.cs:42–103`) keeps a linked cancellation source with a bounded per-check timeout (two seconds by default, options validation caps it at one minute). It performs no retry. Caller cancellation propagates; internal timeout, transport errors, 401/403 and other non-success statuses, malformed/undefined/missing verdicts, invalid scores, missing/invalid metadata or unreadable gateway responses produce a failure decision. Default mode yields FailedClosed. Explicit legacy mode yields FailedOpen. No provider response body or exception message enters diagnostic logging. Layer validation prevents arbitrary returned layer strings from reaching logs (`LlmGuardClient.cs:106–140`).

Incoming middleware returns 403 `prompt_blocked` for denied text, 503 `guard_unavailable` for gateway failure, 503 `payload_unscreenable` with a fixed inspection code for format/extraction failure, or 413 `payload_too_large` for oversize (`LlmGuardMiddleware.cs:36–108`). Outgoing handler throws existing typed `LlmGuardBlockedException` or `LlmGuardUnavailableException` before calling the next handler (`LlmGuardHandler.cs:36–115`). A content allow verdict means only that extracted text passed screening, not that an agent may execute a tool.

| Situation | Before, default behavior | After, default behavior |
|---|---|---|
| Gateway unavailable/timeout/401/403/malformed verdict | Continue with FailedOpen warning | Middleware 503; handler unavailable exception; zero downstream execution |
| Unsupported/missing required payload | Skip extraction and forward; sometimes inspect only recognized fragments | Middleware 503; handler unavailable exception; whole payload must parse before any checks/forwarding |
| Invalid JSON | Skip and forward | Middleware 503; handler unavailable exception |
| Unauthorized/denied content | Middleware 403 or blocked exception | Same rejection, zero downstream execution; this is a content verdict, not tool authorization |
| Valid, screening-allowed content | Forward | Forward with body preserved after all required text checks finish |

Explicit FailOpen can still forward gateway failures or structurally unscreenable content and logs a warning. Oversized and unreadable streams remain closed in both modes; safely replaying partial/truncated content is not possible. This is an intentional legacy-compatibility limit.

## 5. Payload Inspection Changes

`PayloadInspection.cs:6–10` defines internal outcomes: Inspected, UnsupportedFormat, MissingContent, InvalidJson, UnexpectedContentType, OversizedPayload and ExtractionFailure. Gateway unavailable remains the existing FailedClosed/FailedOpen decision rather than a JSON extraction outcome.

The shared reader (`PayloadInspection.cs:39–51`) reads at most `MaxBodyBytes + 1` bytes, allowing oversize detection without unbounded buffering. The same 1-MiB default applies incoming and outgoing. Known Content-Length can reject early; actual bytes are checked too. Bounds precede format fallback, so explicit legacy mode cannot evade the bound with a non-JSON type.

Incoming buffering keeps the request body open and resets Position to zero after successful reading (`LlmGuardMiddleware.cs:56–72`). Unscreenable but fully buffered legacy requests remain readable downstream. Read errors stop immediately with sanitized ExtractionFailure even in legacy mode. Existing length and stream-body oversize tests remain in place. Cancellation propagates and is checked again before downstream invocation (`LlmGuardMiddleware.cs:44,93,120`).

Outgoing handler reads a bounded stream, replaces successfully buffered content with `ByteArrayContent`, copies content headers and disposes the original content (`LlmGuardHandler.cs:49–82`). This preserves the exact screened bytes for provider forwarding. The request owns replacement-content disposal; the shared reader does not dispose caller streams. On read failure or oversize no downstream call occurs, and normal caller/request disposal remains responsible for the rejected request content.

All messages/parts are parsed before the handler starts gateway calls. Invalid later messages cannot be hidden by an earlier valid message. All checks complete through `Task.WhenAll`, then block/failure decisions are evaluated before forwarding; one blocked item stops the entire provider operation (`LlmGuardHandler.cs:80–105`). Existing concurrent-check semantics are retained. Tests use downstream counters and an explicit delayed-message barrier to verify that no partial provider request is sent.

Duplicate property names, including case variants, are rejected recursively (`PayloadInspection.cs:20–35`). This avoids one component screening a value different from the value another JSON parser binds. Unsupported nested content is rejected, never converted by extracting arbitrary strings.

## 6. Supported and Unsupported Payload Schemas

### Incoming middleware

Protected means POST/PUT/PATCH under a configured segment-aware path prefix (`LlmGuardMiddleware.cs:110–112`); default ProtectedRoutes is empty. Other routes and methods are unaffected. Incoming screening inspects the configured exact-case JSON string field, default `prompt`, optionally a nested object path such as `input.text` (`LlmGuardMiddleware.cs:128–168`). It requires a nonempty/non-whitespace string. It does not automatically scan history or arbitrary other JSON fields. This contract must match the downstream endpoint; the sample's outgoing layer additionally scans history.

### Outgoing registered LLM client

Protected means POST/PUT/PATCH on a client explicitly registered with `AddLlmGuardHandler` (`LlmGuardHandler.cs:36–43`). The client is expected to be dedicated to LLM generation traffic. GET/other methods are outside this boundary, preserving operations such as model-list retrieval. Unregistered clients and unrelated clients remain unaffected; a mutating unrelated request on the same registered client must satisfy the supported schema or fails closed. This handler does not transparently discover all LLM calls.

Supported outgoing schemas (`LlmGuardHandler.cs:136–234`):

```json
{"model":"example","prompt":"nonempty completion text"}
```

```json
{"model":"example","messages":[
  {"role":"system","content":"nonempty text"},
  {"role":"user","content":[{"type":"text","text":"first"},{"type":"text","text":"second"}]},
  {"role":"tool","content":"retrieved result text"}
]}
```

Both top-level prompt and messages, if present, must be valid and are screened. Messages must be a nonempty array of objects; supported roles are system, developer, user, assistant, tool and function. Content must be a non-whitespace string or a flat array consisting exclusively of nonempty `type: text` string parts, joined with newlines. Tool/function result content still maps to `source: rag`; the other roles map to user. Role is a parsing/source hint, not a trusted principal or grant.

Both boundaries accept application/json or a media type ending in +json, with UTF-8 or no explicit charset. Missing/unsupported content type, non-UTF-8 charset and Content-Encoding are unavailable. JSON is parsed with bounded default System.Text.Json depth; invalid syntax/depth yields InvalidJson. Required-field matching is exact-case; duplicate properties and case-variant duplicates reject. The complete provider schema is not validated: model/sampling metadata is retained, and arbitrary extra strings are not treated as prompts.

Unsupported outgoing structures fail closed: top-level Responses-style `input`; missing/null/non-array/empty messages; non-object messages; missing/unknown role; null/empty content; object-valued or nested-array content; mixed image/audio/non-text parts; `tool_calls` and `function_call` message structures. Previously mixed text/image arrays skipped image content; now they reject as unsupported. No claim of image/audio screening, full provider compatibility or authorization of tool calls is made. An unrecognized provider may place instructions in additional fields not covered by this adapter; use only the documented contract or add a separately reviewed adapter.

## 7. Security Invariants Verified

- Default failure mode is closed; actual sample configuration binds FailClosed without a test-only default override.
- Timeout, unreachable service, 401/403/500, invalid JSON response, undefined verdict and missing verdict produce zero downstream calls at both boundaries (`HardeningTests.cs:107–136`). Existing client tests also exercise scores, missing layer, invalid JSON types, source contract and both failure modes.
- Missing/unsupported prompt/message structure, invalid JSON, unexpected type, mixed text/image content, nested arrays, duplicate properties and unsupported call structures cannot silently forward under default options (`HardeningTests.cs:27–100`). No gateway calls start when a later message is malformed.
- Valid supported content reaches downstream intact; tool-result source mapping remains; one blocked message prevents forwarding (existing middleware/handler/integration tests).
- Multiple-message screening cannot partially forward: the explicit completion barrier leaves downstream count zero until all checks finish (`HardeningTests.cs:175–197`).
- Cancellation is tested during active gateway screening for both FailClosed and explicit FailOpen, incoming and outgoing. There is exactly one fake gateway call and zero downstream calls; no unguarded retry (`HardeningTests.cs:159–172,219–239`).
- Read exceptions are sanitized and cannot forward in either mode; oversize stops in either mode including non-JSON legacy requests (`HardeningTests.cs:245–296`). Existing incoming tests cover normal and stream request bodies.
- Explicit legacy gateway outage and unscreenable forwarding are documented and tested; a deny verdict still blocks. Unprotected routes, GET requests and unregistered clients remain unaffected (`HardeningTests.cs:139–155,209–216` plus existing tests).
- Synthetic prompts/API keys/provider error strings and untrusted returned layer values do not appear in the changed application diagnostic paths. Inspection warnings use fixed codes only (`Log.cs:29–31`, `HardeningTests.cs:199–207,252–276`, existing privacy tests). Framework/custom logging policies remain the host's responsibility.

Reviewed the complete Phase 1B diff and focused source reads for DI, fallback, schema handling, body stream ownership and compatibility. Phase 1A's authentication/logging/classifier/gateway changes remain as found; this task introduced no Python changes. No policy or user permission is derived from an LLM verdict. The test-host logging change removes machine logging only, not security checks.

## 8. Fresh-Source Build and Test Results

All commands below were run from the repository root. Existing SDK is 9.0.301; projects retain net8.0/C#12. Existing NuGet assets/cache sufficed. No SDK install or NuGet restore ran. `--target:Rebuild` recompiled current source before executing tests with `--no-build`, so results are not from the pre-audit assembly.

### Exact final commands

```powershell
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
dotnet build dotnet/LlmGuard.sln --configuration Release --no-restore --target:Rebuild -p:NuGetAudit=false -m:1

dotnet test dotnet/tests/LlmGuard.Tests/LlmGuard.Tests.csproj --configuration Release --no-build --no-restore --filter FullyQualifiedName~HardeningTests --logger 'console;verbosity=minimal'

dotnet test dotnet/tests/LlmGuard.Tests/LlmGuard.Tests.csproj --configuration Release --no-build --no-restore --logger 'console;verbosity=minimal'

& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
```

| Verification | Final result |
|---|---|
| Fresh solution Release Rebuild | PASS, 0 warnings, 0 errors, 5.68 seconds |
| Focused fresh HardeningTests | 43 passed / 0 failed / 0 skipped |
| Full fresh .NET suite | 104 passed / 0 failed / 0 skipped |
| Existing offline Python suite | 128 passed / 0 failed / 0 errors / 0 skipped / 0 deselected, 49.33 seconds |
| `git diff --check` | PASS |

The solution build includes library, sample, test project and overhead benchmark project, without running the benchmark. Focused cases are a subset of the full .NET result; do not add their counts. The Python suite includes local-model tests under the existing Phase 1A offline runner. Python was run after .NET implementation began; subsequent changes were confined to .NET/docs. No Python source changed after its passing run.

### Intermediate results and environmental limits

The first restricted build used the same build command without `-m:1` and returned Build FAILED with zero warnings/errors and no detailed cause. It was retried outside the sandbox with explicit approval, no restore and serial build; it succeeded. Later rebuilds used the same approved offline command after source/test corrections. Successful intermediate rebuild durations were 12.57, 8.26, 10.15 and 5.48 seconds before the final 5.68-second build. No diagnosis beyond restricted build-context failure is claimed for the initial silent failure.

Intermediate focused/full suites passed 37/98 tests. Added stream/cancellation cases then exposed one timing-dependent test failure: **41 passed, 1 failed**, with `Assert.Single` seeing zero gateway calls because its 50-ms cancellation timer could fire before gateway dispatch. The test was corrected to synchronize on a fake gateway-start signal, then explicitly cancel; this strengthens the intended mid-screening assertion rather than weakening security behavior. After correction, focused/full suites passed 42/103. Adding missing-verdict boundary coverage and checking the sample's actual config yielded the final 43/104 above.

Tests ran in-memory with fake gateway/provider handlers; there was no running gateway, provider, external network service or model API. The sample tests clear logging providers in their WebApplicationFactory host to avoid Windows Event Log write privileges; separate capturing logger tests verify privacy. No Event Log failure occurred in the fresh suites, and no global logging permission change was made. Fresh success does not establish the original three baseline failures were caused exclusively by Event Log rather than any other stale-assembly differences.

The first sandboxed Python attempt repeated the known temporary-directory fixture permission problem, printed progress with an error, and was interrupted without a valid aggregate. Approved execution outside the sandbox then passed all 128 tests using the unchanged existing offline runner. Downloads and real HTTP transports were blocked by that runner; loopback support remains for asyncio. No test was disabled to obtain the final Python result.

## 9. Backward-Compatibility Impact

- Default FailOpen becomes FailClosed. Existing deployments that deliberately require legacy availability must explicitly configure FailOpen and accept unscreened execution risk.
- Protected payloads formerly skipped now produce structured unavailable results or exceptions by default. Incoming non-JSON and missing prompt now return 503 rather than silently executing. This is a deliberate security-contract change.
- Mixed multimodal arrays, missing/empty fields and partially recognized conversations are rejected, rather than screening only recognized fragments. Future provider adapters require explicit design/review.
- MaxBodyBytes now also limits outgoing request bodies. Oversize/read errors are always closed, even with legacy FailOpen.
- Gateway metadata must have a recognized layer and present finite nonnegative latency. A nonconforming custom gateway becomes unavailable rather than passing arbitrary metadata to logs.
- Existing public types, enum numeric values, ILlmGuardClient and exception constructors remain. The original two-argument handler constructor is retained and uses safe defaults for inspection. A new three-argument overload accepts configured IOptions; DI selects that overload. Manual construction with custom FailOpen/size choices should supply the options overload consistently with the gateway client.
- Outgoing protection scope is now explicitly POST/PUT/PATCH. Other methods pass through; do not place generation or sensitive actions on unsupported methods and assume this adapter protects them. Unregistered clients remain unprotected.
- Sample config changes only failure mode; its registered outgoing client and fake-provider behavior remain. Incoming body-only prompt screening is supplemented by outgoing full-history text screening in the sample. No real provider compatibility beyond the documented format was tested.

## 10. Remaining Limitations

- This is content screening, not deterministic action authorization, principal/tenant isolation, MCP interception or provenance enforcement. A classifier allow never grants tool permissions.
- Only configured incoming route/method/field combinations and explicitly registered outgoing clients/methods are covered. Direct SDK calls, unregistered clients, tool execution, alternate protocols and other methods can bypass this opt-in integration.
- Incoming middleware validates one prompt field, not all possible endpoint inputs. Outgoing supports documented text chat/completion structures only. An application accepting additional instruction fields needs its own reviewed adapter. Provider metadata/custom formats are not generically interpreted.
- Caller cancellation and per-check timeout are bounded; there is no new global multi-message concurrency cap, policy engine, output screening, rate limiting, HTTP redirect policy, credential rotation or retry framework. Many small messages within the byte bound can still consume gateway capacity.
- Trusted custom ILlmGuardClient implementations and manually constructed option objects must honor the same contract; startup validation applies to DI configuration. This library is not an enforcement boundary against malicious code in the host process.
- JSON bodies are buffered; incoming ASP.NET buffering may use its normal temporary file behavior. Production temp-file/log retention/access, TLS, reverse proxy and host diagnostics require deployment configuration. Existing length/hash logging permits correlation and dictionary guesses; it is not anonymization.
- Fake handlers establish local boundary behavior, not external-provider semantics or a deployed-system penetration test. Build success uses installed SDK 9 targeting net8.0; CI's separate SDK8 execution was not run here.
- The restricted Windows execution environment still needs an approved context for solution rebuild/Python temp artifacts. No global settings were changed; no build/download was attempted to bypass missing caches.

## 11. Git Status and Commands Executed

Branch: `dotnet-middleware`. HEAD remains `9a139e05fd4d8ed12bc0df2bb06fd171736f4bc6`. Phase 1A's pre-existing modified/untracked state and the untracked baseline/Phase 1A reports were preserved. Phase 1B adds the 17 files/changes listed in section 3: 14 tracked .NET files modified, two new .NET files and this new report. Ignored generated .NET build artifacts and test temporary files are not source changes. No staging, commit, push, history rewrite or identity/GitHub configuration change occurred.

Read-only inspection commands: `Get-Content` of attached brief, baseline/Phase 1A reports, requested .NET source, tests, project/sample configuration and docs; `Get-ChildItem` for sample launch files; `rg --files --hidden -g AGENTS.md -g '!venv/**' -g '!.git/**'` (no applicable repository instruction file found); `rg -n` for behavior/cancellation/logging and line references; `git status --short`, `git status --short --untracked-files=all`, `git branch --show-current`, `git rev-parse HEAD`, `git diff --check`, `git diff --stat -- dotnet`, `git diff --numstat -- dotnet` and focused `git diff -- <changed dotnet paths>`. Some combined read output was truncated, followed by targeted source/diff reads. Edits used `apply_patch`. Exact build/test commands and all material failed/intermediate runs are in section 8. Environment assignments affect only the command process, not global configuration.

## 12. Recommended Next Step

Review Phase 1B's deliberate default/schema compatibility changes and remaining registration/format limits. After reviewer approval, select the next isolated authorization-contract/MCP milestone from the baseline plan. No such implementation begins here. Stop after Phase 1B; no OPA, provenance, deployment or unrelated refactoring is included.
