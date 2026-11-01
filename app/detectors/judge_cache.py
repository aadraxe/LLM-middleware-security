"""
judge_cache.py
Groq call for the LLM-as-judge layer, with optional disk caches.

Default (no cache env var set): one plain POST, as the gateway always did.

Two caches, both of which also retry 429 / 5xx with backoff and store the
latency of the original (uncached) call so benchmarks can report real latency:

  JUDGE_CACHE_JSONL=<file.jsonl>   (current) one JSON line per verdict, keyed by
      the SHA-256 of the exact prompt text sent to the judge, plus the template
      (SHA-256 of the system prompt), model and temperature. Re-runs reuse
      verdicts; a verdict made under different settings is never reused.

  JUDGE_CACHE_DIR=<dir>            (legacy) one JSON file per verdict, keyed by
      hash(model, system prompt, user content). Holds the earlier run's
      default-temperature verdicts so those results stay reproducible.

JUDGE_TEMPERATURE sets the sampling temperature (default 0). The value
"default" omits the parameter, which is how the earlier run was made.
"""

import hashlib
import json
import os
import time

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# Groq retired llama-3.3-70b-versatile; gpt-oss-120b is the default replacement.
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "openai/gpt-oss-120b")


def judge_temperature():
    """None means 'don't send a temperature' (Groq's default, 1.0)."""
    value = os.environ.get("JUDGE_TEMPERATURE", "0")
    return None if value == "default" else float(value)


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
    temperature = judge_temperature()
    if temperature is not None:
        body["temperature"] = temperature
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


def _post_with_retry(system_prompt, user_content, groq_key, timeout) -> dict:
    delay = 5.0
    import httpx
    data = {"_status": None, "error": {"message": "network error on every attempt"}}
    for attempt in range(8):
        start = time.perf_counter()
        try:
            data = _post(system_prompt, user_content, groq_key, timeout)
        except httpx.TransportError as e:
            # Timeouts / dropped connections: retry rather than fail open
            print(f"[JUDGE] {type(e).__name__}, retrying in {delay:.0f}s", flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 120)
            continue
        data["_latency_ms"] = (time.perf_counter() - start) * 1000
        if "choices" in data:
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


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class JsonlVerdictCache:
    """Append-only JSONL verdict store, loaded into memory once per path."""

    def __init__(self, path: str):
        self.path = path
        self.entries = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line)
                        self.entries[self.key(rec["prompt_sha256"], rec["template_sha256"],
                                              rec["model"], rec["temperature"])] = rec

    @staticmethod
    def key(prompt_sha, template_sha, model, temperature):
        return (prompt_sha, template_sha, model, temperature)

    def get(self, system_prompt, user_content):
        return self.entries.get(self.key(sha256(user_content), sha256(system_prompt),
                                         JUDGE_MODEL, judge_temperature()))

    def put(self, system_prompt, user_content, data):
        rec = {
            "prompt_sha256": sha256(user_content),
            "template_sha256": sha256(system_prompt),
            "model": JUDGE_MODEL,
            "temperature": judge_temperature(),
            "content": data["choices"][0]["message"]["content"],
            "latency_ms": round(data["_latency_ms"], 1),
            "usage": data.get("usage", {}),
            "created": int(time.time()),
        }
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        self.entries[self.key(rec["prompt_sha256"], rec["template_sha256"],
                              rec["model"], rec["temperature"])] = rec


_jsonl_caches = {}


def judge_request(system_prompt: str, user_content: str, groq_key: str,
                  timeout: float = 15.0) -> dict:
    """Return Groq's JSON response; adds `_latency_ms` (and `_cached` when from disk)."""
    jsonl_path = os.environ.get("JUDGE_CACHE_JSONL")
    if jsonl_path:
        cache = _jsonl_caches.setdefault(jsonl_path, JsonlVerdictCache(jsonl_path))
        rec = cache.get(system_prompt, user_content)
        if rec:
            return {"choices": [{"message": {"content": rec["content"]}}],
                    "_latency_ms": rec["latency_ms"], "_cached": True}
        data = _post_with_retry(system_prompt, user_content, groq_key, timeout)
        if "choices" in data:
            cache.put(system_prompt, user_content, data)
        return data

    cache_dir = os.environ.get("JUDGE_CACHE_DIR")
    if not cache_dir:
        start = time.perf_counter()
        data = _post(system_prompt, user_content, groq_key, timeout)
        data["_latency_ms"] = (time.perf_counter() - start) * 1000
        return data

    # Legacy key has no temperature: it only ever held default-temperature verdicts
    key = hashlib.sha256(f"{JUDGE_MODEL}\n{system_prompt}\n{user_content}".encode()).hexdigest()
    path = os.path.join(cache_dir, f"{key}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["_cached"] = True
        return data
    data = _post_with_retry(system_prompt, user_content, groq_key, timeout)
    if "choices" in data:
        os.makedirs(cache_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    return data
