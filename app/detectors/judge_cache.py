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
JUDGE_MODEL = "llama-3.3-70b-versatile"


def _post(system_prompt: str, user_content: str, groq_key: str, timeout: float) -> dict:
    import httpx
    response = httpx.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
        json={
            "model": JUDGE_MODEL,
            "max_tokens": 200,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        },
        timeout=timeout,
    )
    data = response.json()
    data["_status"] = response.status_code
    return data


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
        print(f"[JUDGE] status {data.get('_status')}, retrying in {delay:.0f}s", flush=True)
        time.sleep(delay)
        delay = min(delay * 2, 120)
    return data
