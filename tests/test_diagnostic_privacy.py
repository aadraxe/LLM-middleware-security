"""Synthetic provider failures must not leak bodies, prompts or credentials."""
import pytest

from app.detectors import jailbreak_detector, prompt_injection_detector, judge_cache
from app.services.llm_service import call_llm


@pytest.mark.parametrize("judge", [jailbreak_detector.llm_judge, prompt_injection_detector.llm_judge])
@pytest.mark.parametrize("failure", ["exception", "body"])
def test_judge_diagnostics_are_private(monkeypatch, capsys, caplog, judge, failure):
    secret = "synthetic-provider-error-privacy-716"
    monkeypatch.setenv("GROQ_API_KEY", secret)
    def request(*args, **kwargs):
        if failure == "exception":
            raise RuntimeError(secret)
        return {"error": secret}
    monkeypatch.setattr(judge_cache, "judge_request", request)
    attack, _, reason = judge(secret)
    assert attack is False and secret not in reason
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err + caplog.text


def test_provider_exception_text_is_private(monkeypatch, capsys, caplog):
    import httpx
    secret = "synthetic-provider-error-privacy-716"
    monkeypatch.setenv("GROQ_API_KEY", secret)
    def fail(*args, **kwargs):
        raise RuntimeError(secret)
    monkeypatch.setattr(httpx, "post", fail)
    assert call_llm(secret) == "[LLM error: generation unavailable]"
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err + caplog.text
