"""
judge_cache.py
Groq call for the LLM-as-judge layer, with an optional disk cache.

Default (JUDGE_CACHE_DIR unset): one plain POST, exactly as before.

With JUDGE_CACHE_DIR set (benchmarks): verdicts are cached on disk keyed by a
hash of (model, system prompt, user content), and 429 / 5xx responses are
retried with exponential backoff. Re-runs read from cache, cost no tokens,
and give identical results. The latency of the original (uncached) call is
stored with each entry so benchmarks can still report real judge latency.
"""

import hashlib
import json
import os
import time

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# Groq retired llama-3.3-70b-versatile; gpt-oss-120b is the default replacement.
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "openai/gpt-oss-120b")


def _post(system_prompt: str, user_content: str, groq_key: str, timeout: float) -> dict:
    import httpx
    body = {
        "model": JUDGE_MODEL,
        "max_tokens": 200,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }
    if JUDGE_MODEL.startswith("openai/gpt-oss"):
        # Reasoning model: keep reasoning short and out of the content field,
        # and leave room for reasoning tokens before the JSON verdict.
        body.update(max_tokens=600, reasoning_effort="low", include_reasoning=False)
    response = httpx.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
        json=body,
        timeout=timeout,
    )
    data = response.json()
    data["_status"] = response.status_code
    data["_retry_after"] = float(response.headers.get("retry-after", 0) or 0)
    return data


class DailyLimitReached(RuntimeError):
    """Groq's per-day quota is used up; retrying today won't help."""


def judge_request(system_prompt: str, user_content: str, groq_key: str,
                  timeout: float = 15.0) -> dict:
    """Return Groq's JSON response; adds `_latency_ms` (and `_cached` when from disk)."""
    cache_dir = os.environ.get("JUDGE_CACHE_DIR")
    if not cache_dir:
        start = time.perf_counter()
        data = _post(system_prompt, user_content, groq_key, timeout)
        data["_latency_ms"] = (time.perf_counter() - start) * 1000
        return data

    key = hashlib.sha256(f"{JUDGE_MODEL}\n{system_prompt}\n{user_content}".encode()).hexdigest()
    path = os.path.join(cache_dir, f"{key}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["_cached"] = True
        return data

    delay = 5.0
    for attempt in range(8):
        start = time.perf_counter()
        data = _post(system_prompt, user_content, groq_key, timeout)
        data["_latency_ms"] = (time.perf_counter() - start) * 1000
        if "choices" in data:
            os.makedirs(cache_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            return data
        if data.get("_status") not in (429, 500, 502, 503):
            return data  # non-retryable: don't cache, let the caller handle it
        message = str(data.get("error", {}).get("message", ""))
        if "per day" in message:
            raise DailyLimitReached(message[:200])
        wait = data.get("_retry_after") or delay
        print(f"[JUDGE] status {data.get('_status')}, retrying in {wait:.0f}s", flush=True)
        time.sleep(wait + 0.5)
        delay = min(delay * 2, 120)
    return data
