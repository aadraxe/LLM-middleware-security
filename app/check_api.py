"""
check_api.py
POST /v1/check: screen one piece of text and return a verdict, without
calling the protected LLM. Used by clients such as the .NET LlmGuard package.

Auth: X-API-Key must match one of the comma-separated keys in the
GATEWAY_API_KEYS environment variable (constant-time comparison). With no
keys configured every request is rejected.

Logging: one line per check in the security event log with the verdict, layer,
score, source, text length and SHA-256 of the text. The text itself is not logged.
"""

import hmac
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.gateway_state import get_pipeline
from app.models.schemas import CheckRequest, CheckResponse, PipelineResult

API_KEYS_ENV = "GATEWAY_API_KEYS"
log = logging.getLogger("gateway.check")
router = APIRouter()

# Pipeline-internal layer names → the four layers in the public contract
_LAYER_MAP = {
    "regex": "rules",
    "rules": "rules",
    "fuzzy": "fuzzy",
    "finetuned_classifier": "classifier",
    "llm_judge": "judge",
}


def _configured_keys():
    return [k.strip() for k in os.environ.get(API_KEYS_ENV, "").split(",") if k.strip()]


def require_api_key(request: Request, x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    keys = _configured_keys()
    if not keys:
        log.warning("%s is not set; rejecting authenticated requests", API_KEYS_ENV)
    presented = (x_api_key or "").encode("utf-8")
    # Compare against every key (no early exit) so timing doesn't reveal which one matched
    matched = False
    for key in keys:
        matched |= hmac.compare_digest(presented, key.encode("utf-8"))
    if len(request.headers.getlist("X-API-Key")) != 1 or not x_api_key or not matched:
        raise HTTPException(status_code=401, detail="Missing or invalid API key",
                            headers={"WWW-Authenticate": "ApiKey"})


def decision_layer(result: PipelineResult) -> str:
    """The stage that made the final decision, in contract terms."""
    if "TieredPipeline" in result.detector_results:  # local_only / cascade
        return _LAYER_MAP[result.detector_results["TieredPipeline"]["detection_layer"]]

    # ThreatPipeline (full, legacy backends)
    if not result.allowed and result.blocking_detector in result.detector_results:
        layer = result.detector_results[result.blocking_detector]["detection_layer"]
        return _LAYER_MAP.get(layer, "rules")
    # Allowed: report the most expensive stage that ran and let it through
    ran = {k for d in result.detector_results.values() for k in (d.get("layer_scores") or {})}
    if "llm_judge" in ran:
        return "judge"
    if "finetuned_classifier" in ran:
        return "classifier"
    return "fuzzy" if "fuzzy" in ran else "rules"


def _log_check(source, text, verdict, layer, score, latency_ms):
    from app.main import log_security_event  # late import: main imports this module
    log_security_event("/v1/check", text, verdict, latency_ms,
                       source=source, layer=layer, score=score)


@router.post("/v1/check", response_model=CheckResponse, dependencies=[Depends(require_api_key)],
             description="Requires X-API-Key matching GATEWAY_API_KEYS. Screens text without generation.")
def check(request: CheckRequest) -> CheckResponse:
    start = time.perf_counter()
    try:
        result = get_pipeline().analyze(request.text)
        layer = decision_layer(result)
    except Exception:
        from app.main import log_security_event
        log_security_event("/v1/check", request.text, "error",
                           round((time.perf_counter() - start) * 1000, 2),
                           source=request.source, error_category="analysis_error")
        raise HTTPException(status_code=503, detail="Security analysis unavailable") from None
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    verdict = "allow" if result.allowed else "block"
    score = float(result.risk_score)
    _log_check(request.source, request.text, verdict, layer, score, latency_ms)
    return CheckResponse(verdict=verdict, score=score, layer=layer, latency_ms=latency_ms)
