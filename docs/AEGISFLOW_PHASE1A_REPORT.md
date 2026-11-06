# AegisFlow Phase 1A report

## 1. Summary of changes

Phase 1A addresses AF-01 and AF-02 from `docs/AEGISFLOW_BASELINE_AUDIT.md`, which was read before implementation. `/secure-chat` now uses the same client API-key authentication as `/v1/check`. Chat audit events contain structured metadata instead of raw prompts, histories or detector output. Provider diagnostics and exception text are sanitized. Existing detection algorithms, thresholds, pipeline selection, checkpoint loading and downstream request construction are unchanged.

No .NET changes, MCP/OPA/provenance implementation, dependency installation, model downloads, training, external API requests, AWS access, commits, pushes or Git configuration changes were performed.

## 2. Modified files

| File | Change |
|---|---|
| `app/main.py` | Shared auth dependency on chat; common metadata event builder; sanitized analysis/unexpected generation errors; per-request correlation ID. |
| `app/check_api.py` | Shared dependency rejects duplicate headers; endpoint-neutral missing-configuration warning; common safe audit metadata and sanitized analysis failure. Successful response contract unchanged. |
| `app/detectors/jailbreak_detector.py` | Remove diagnostic printing of provider body/error text; keep benign/unavailable return values and failure prefixes. |
| `app/detectors/prompt_injection_detector.py` | Replace exception text in unavailable reason with a fixed message. |
| `app/services/llm_service.py` | Replace exception interpolation in existing error response with a fixed message. |
| `tests/test_check_endpoint.py` | Update chat auth expectation; add authentication, side-effect prevention, structured audit privacy, sanitized errors and request-ID tests. |
| `tests/test_diagnostic_privacy.py` (new) | Synthetic judge/provider diagnostic privacy regression tests. |
| `tests/run_offline.py` (new) | Credential-free, HTTP-blocked, offline pytest runner using existing dependencies. |
| `conftest.py` | Route test-only temporary files/probes to ignored `.test-tmp/`. Existing dotenv suppression retained. |
| `pytest.ini` (new) | Explicit test base directory `.test-tmp/pytest`. |
| `.gitignore` | Ignore `.test-tmp/`. |
| `README.md` | Document auth requirement, safe log schema, compatibility changes and hash privacy limitations. |
| `docs/AEGISFLOW_PHASE1A_REPORT.md` (new) | This report. |

`docs/AEGISFLOW_BASELINE_AUDIT.md` was already present and untracked when this task began; it was not modified. `app/models/schemas.py` was inspected and needed no changes. No C# source or .NET configuration changed.

## 3. Authentication implementation

`secure_chat` declares `Depends(check_api.require_api_key)` at the route level, so the body handler cannot perform analysis or generation before the shared dependency succeeds. The dependency reads only the `X-API-Key` header and operator-controlled `GATEWAY_API_KEYS`. It compares against every configured key using `hmac.compare_digest`. Missing/invalid/empty/malformed or duplicate credentials and missing/blank key configuration result in 401 with `WWW-Authenticate: ApiKey`.

Duplicate headers are rejected even if one or both contain a configured key, avoiding ambiguous first-header behavior. Comma-concatenated credentials do not match an individual configured key. Header documentation and the README explain the contract. Keys are never hard-coded in application code; test keys are synthetic fixtures. Body fields, prompt instructions, roles, tenants and permission claims cannot grant access. This authenticates possession of a configured client key, not an individual user's identity or tool permissions.

Normal FastAPI startup still builds the configured pipeline. The no-execution guarantee is about unauthenticated request analysis/inference/generation; this change does not defer existing model initialization until authentication.

## 4. Logging privacy implementation

Both endpoints use `log_security_event`, backed by the existing local JSONL writer. The event schema is:

```text
request_id, timestamp, endpoint, source, text_length, text_sha256,
verdict, layer, score, latency_ms, error_category
```

UUID request IDs and timezone-aware UTC timestamps are server-generated. Layer names are mapped to the existing public fixed vocabulary. Verdicts are allow/block/error. Failure categories are fixed `analysis_error` or `provider_error`, never exception messages. No prompt, conversation history, header, credential, triggered-rule list, free-form threat/reason or complete detector object is passed to the writer. Chat decision and unexpected provider-error events share the same request ID. Analysis latency is recorded on the decision event; provider-error latency is elapsed request-handler time. An allow event records a screening decision, not proof generation succeeded.

Deterministic SHA-256 permits correlation of repeated prompts and dictionary guessing of predictable inputs. It is retained for consistency with existing check logs and debugging, not anonymization or proof of provenance. Restrict access and retention. Existing historical raw-prompt logs are not automatically deleted or rewritten by this task.

Analysis failures produce a metadata error event and sanitized 503, preventing downstream generation. Unexpected exceptions escaping `call_llm` produce a metadata error event and sanitized 502. The existing provider wrapper still returns an error string on its own caught failures; that string is now fixed and does not expose exception text. Its existing allowed-response behavior is preserved, so these internally caught provider errors do not produce a separate provider-error audit event. Judge errors retain existing detection/fallback semantics but no longer print raw provider bodies or exception text. No detector decision algorithm or failure-prefix matching was changed.

## 5. Tests executed and results

Commands ran from the repository root with `venv/Scripts/python.exe`, Python 3.13.9. No packages were installed. The safe runner clears inherited gateway/Groq keys, pipeline/cache overrides, disables dotenv through existing conftest, disables pytest plugin autoload, enables Hugging Face/transformers offline mode, disables telemetry, blocks real synchronous/asynchronous httpx HTTP transports and blocks non-loopback socket connect/connect_ex. Loopback is permitted for Windows asyncio socketpair initialization; endpoint tests use TestClient's in-process transport. This is a guard for the inspected suite, not a general network sandbox against arbitrary code or subprocesses. Tests never invoke a live provider or training job. CPU thread counts are bounded for the test process only.

### Completed verification

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/test_check_endpoint.py tests/test_diagnostic_privacy.py -q -p no:cacheprovider -k 'not real_local_only_pipeline' --tb=short
```

**46 passed, 0 failed, 0 errors, 0 skipped, 1 deselected**, 1.55 seconds. The one deselected test was real local-model endpoint inference; it was subsequently included in the full suite.

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider --tb=short
```

**128 passed, 0 failed, 0 errors, 0 skipped, 0 deselected**, 55.78 seconds in the first completed full run. This included all three real-model tests. The run paused for a substantial period at the model-inclusive portion; an interruption was requested, but by then the process had completed with exit code 0 and the aggregate above. An intermediate progress update incorrectly described it as stalled; the completed result supersedes that description. No interrupted-run aggregate was substituted for the actual result.

```powershell
& venv/Scripts/python.exe -B tests/run_offline.py tests/ -q -p no:cacheprovider -k 'not real_local_only_pipeline and not real_model_smoke and not default_gateway_pipeline_runs_local_only' --tb=short
```

**125 passed, 0 failed, 0 errors, 0 skipped, 3 deselected**, 2.07 seconds. Only three real-model inference tests were deselected. This follow-up is overlapping evidence, not an additional 125 distinct tests. The missing-model configuration test remained enabled and passed.

The exact full-suite command above was issued again after the final request-ID correction: **128 passed, 0 failed, 0 errors, 0 skipped, 0 deselected**, 44.58 seconds, exit code 0. This is the final-source verification result. The full run includes **42 endpoint regression tests** and **5 diagnostic privacy tests**; all passed. Counts across runs overlap and must not be summed.

Authentication cases actually exercised: missing, wrong, empty, Bearer-prefixed, comma-concatenated, valid-plus-invalid duplicate and valid-plus-valid duplicate credentials on both endpoints; missing/empty/comma-only key configuration for chat; valid chat credentials; multiple configured valid check keys; check missing-configuration rejection; body claims cannot substitute for credentials. Rejection tests assert zero analysis and zero generation calls. Existing `/v1/check` allow/block response fields, source defaults, invalid input, layer mapping and log privacy tests executed. Chat allow/block privacy tests inject synthetic secrets into prompts, history, detector rules, detector explanation and provider-key environment; none appear in audit output or captured application diagnostics. Error tests inject synthetic secret-bearing exceptions into analysis and generation, verify sanitized status/body/logs and ensure analysis failure never generates. Diagnostic tests cover missing provider choices and exception cases for both judges and the provider wrapper.

### Environment diagnosis and unsuccessful preliminary attempts

The initial targeted command used an inline socket guard:

```powershell
& venv/Scripts/python.exe -B -c "import os,socket; [os.environ.pop(k,None) for k in ('GROQ_API_KEY','GATEWAY_API_KEYS','PIPELINE_MODE','CLASSIFIER_BACKEND','LOCAL_CLASSIFIER_PATH','JUDGE_CACHE_JSONL','JUDGE_CACHE_DIR','CASCADE_CONFIG')]; os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1'); socket.socket.connect=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('Network disabled for tests')); socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('Network disabled for tests')); import pytest; raise SystemExit(pytest.main(['tests/test_check_endpoint.py','tests/test_diagnostic_privacy.py','-q','-p','no:cacheprovider','-k','not real_local_only_pipeline','--tb=short']))"
```

It encountered repeated fixture errors and ultimately an unhandled pytest session-cleanup `PermissionError` on `.test-tmp/pytest`; no reliable aggregate was printed. A Ctrl+C was sent while it was progressing. A rerun outside the sandbox used the same command with `'-x'` appended to pytest arguments: **1 error, 1 deselected**, stopped at the first error. That failure was the guard blocking `socket.socketpair()` while initializing Windows asyncio, not an authentication assertion failure. The corrected runner resolved that issue without disabling endpoint tests.

Explicit workspace temp configuration alone did not make pytest directories accessible to the restricted execution identity. Inspection of installed pytest showed base directories created with mode `0o700`; the restricted identity could create/find the path but could not scan it. The interaction with Windows restricted execution remains an environment limitation; no claim is made that global Windows ACLs were defective. The successful runs used explicitly approved execution outside the sandbox with the same ignored workspace temp paths and offline guards. No global permissions, Git settings or machine security settings were changed. Future restricted-identity runs may still require an appropriately permitted execution context. Pytest manages only its dedicated base directory; artifacts remain ignored.

Read-only verification commands included `Get-Content` of the task, baseline audit, affected source/tests, README and installed pytest temp implementation; `rg --files` for instruction/test inventory; `rg -n` for auth/log/exception callsites; `Get-Item`/`Get-Acl` on `.test-tmp`; `git status --short --untracked-files=all`, `git branch --show-current`, `git rev-parse HEAD`, `git diff --check`, `git diff --stat`, `git diff --numstat`, and focused `git diff -- <affected application paths>`. `New-Item -ItemType Directory -Path .test-tmp -Force | Out-Null` prepared the ignored workspace root. Edits used `apply_patch`. `git diff --check` passed. No .NET tests were run for this Python-only task.

## 6. Remaining limitations

- Shared keys provide client authentication only; no individual identity, tenant isolation, per-action authorization, rotation service, rate limit or quota mechanism was introduced.
- Authentication does not harden .NET defaults or payload extraction gaps; those findings remain for a separate reviewed task.
- Judge failure fallback, classifier truncation and existing provider wrapper failure semantics remain unchanged except sanitized text. Content classifiers are not permission systems.
- Existing chat/history bounds, production ingress/TLS, file log retention/access/rotation and optional judge caches were not redesigned. Private historical logs need an operator-controlled retention/migration decision.
- `/` and standard FastAPI documentation remain publicly accessible. The task protects generation and preserves the existing check contract.
- Auth/validation rejections do not create security JSONL events; authenticated screening and unexpected processing failures do. Framework/proxy/third-party logging configuration must also avoid body/header logging; tests cover application-controlled paths, not arbitrary deployment middleware.
- Audit write failures do not silently permit generation: the pre-generation write still occurs before the LLM call and exceptions stop processing. No distributed durability or concurrent multi-process log guarantee was added.
- Full-model smoke tests validate local load/inference and selected behavior, not broad classifier effectiveness or new benchmark results.

## 7. Compatibility changes

Intentional: chat now requires the existing API-key header and rejects unauthorized requests with 401. Both endpoints reject duplicate API-key headers. Missing configuration remains fail-closed. Shared dependency now requires FastAPI's injected `Request`; direct Python callers of that internal dependency must supply it.

Successful `/v1/check` HTTP response schema and scores/layers remain unchanged; its audit event gains request ID/error category fields. Chat response schema and normal verdict/generation behavior remain unchanged. The old chat audit fields (`prompt`, `allowed`, `risk_score`, threat/rule/detector objects) are replaced by the common safe schema. Consumers must migrate to `verdict`/`score`/`layer` and metadata. Runtime analysis exceptions now yield sanitized 503 rather than an unhandled 500. Unexpected generation exceptions yield sanitized 502. Internally caught provider failures retain the existing error-string response form with generic text. No secret-bearing exception or provider diagnostic details are returned/printed by the changed paths.

## 8. Security verification

Reviewed final application diff for bypasses, dependency wiring, sensitive log inputs, error propagation, contract compatibility, model execution and fail-open regressions. Both routes share one constant-time key matcher; neither trusts identity assertions in request bodies. Duplicate headers fail closed. Unauthorized requests execute neither handler analysis nor generation. Rule/threshold/model callsites and downstream payload construction are unchanged. No added detector error path forwards to the LLM. No free-form detector fields reach the audit writer. Existing judge failure prefixes survive sanitization so cascade routing remains compatible. Synthetic secret tests cover captured stdout/stderr and logger output as well as JSONL.

The helper takes only metadata fields used by trusted server callsites; the low-level `log_event` remains an internal generic writer for compatibility. This is not a process-wide interception of every possible logger. No model-granted permissions or auth bypass configuration was added. No .NET source, dependencies, checkpoint, split, benchmark result or baseline report was changed.

## 9. Git working-tree status

Branch: `dotnet-middleware`; HEAD: `9a139e05fd4d8ed12bc0df2bb06fd171736f4bc6`. Existing untracked baseline audit preserved. Phase 1A leaves nine tracked files modified and four new files untracked, including this report (listed in section 2); `.test-tmp/` is ignored. No staged changes, commits or pushes were made, and Git identity/configuration was not changed. Final terminal output records status and diff summary.

## 10. Recommended next step

Architecture reviewer should review this narrow authentication/log privacy change and the remaining operational test-context limitation. After approval, select the next scoped hardening or authorization milestone from the baseline audit. Stop after Phase 1A; no .NET hardening, MCP interception, OPA or provenance implementation is included.
