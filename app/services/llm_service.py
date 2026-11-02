"""
llm_service.py
The PROTECTED LLM behind the gateway — the model a real user is chatting with.

Uses Groq's free API if GROQ_API_KEY is set; otherwise falls back to a mock
response so the gateway always runs even without any API key.
"""

import os


def call_llm(prompt: str) -> str:
    groq_key = os.environ.get("GROQ_API_KEY", "")

    # Fallback mock — runs with zero setup
    if not groq_key:
        return f"[MOCK LLM — no GROQ_API_KEY set] You said: {prompt}"

    # Real Groq call (free tier)
    try:
        import httpx
        response = httpx.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {groq_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": os.environ.get("LLM_MODEL", "openai/gpt-oss-120b"),
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            },
            timeout=30.0,
        )
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except Exception:
        return "[LLM error: generation unavailable]"
