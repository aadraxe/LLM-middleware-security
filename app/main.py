from fastapi import Depends, FastAPI, HTTPException
from datetime import datetime, timezone
import hashlib
import json
import os
import time
from uuid import uuid4

try:
    # Pick up GROQ_API_KEY / CLASSIFIER_BACKEND from a local .env if present
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from contextlib import asynccontextmanager

from app.models.schemas import ChatRequest, ChatResponse
from app.gateway_state import get_pipeline
from app.services.llm_service import call_llm
from app import check_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Build the pipeline at startup (PIPELINE_MODE: local_only by default, cascade or
    # full) so a missing model fails immediately rather than on the first request.
    get_pipeline()
    yield


app = FastAPI(
    title="Secure LLM Gateway",
    description="Multi-layer middleware detecting jailbreaks and prompt injection before prompts reach an LLM.",
    version="0.3.0",
    lifespan=lifespan,
)
app.include_router(check_api.router)

LOG_FILE = "app/logs/security_events.jsonl"


def log_event(event: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def log_security_event(endpoint, text, verdict, latency_ms, *, layer=None,
                       score=None, source="user", error_category=None, request_id=None):
    """Only metadata: never accept detector explanations or exception text."""
    log_event({
        "request_id": request_id or str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "source": source,
        "text_length": len(text),
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "verdict": verdict,
        "layer": layer,
        "score": score,
        "latency_ms": latency_ms,
        "error_category": error_category,
    })


@app.get("/")
def root():
    return {
        "message": "Secure LLM Gateway is running",
        "version": "0.3.0",
        "detectors": [d.name for d in get_pipeline().detectors],
    }


@app.post("/secure-chat", response_model=ChatResponse,
          dependencies=[Depends(check_api.require_api_key)],
          description="Requires X-API-Key matching GATEWAY_API_KEYS. Authenticates the client, not an end user.")
def secure_chat(request: ChatRequest):
    start = time.perf_counter()
    request_id = str(uuid4())
    try:
        result = get_pipeline().analyze(
            request.prompt,
            conversation_history=request.conversation_history,
        )
        layer = check_api.decision_layer(result)
    except Exception:
        log_security_event("/secure-chat", request.prompt, "error",
                           round((time.perf_counter() - start) * 1000, 2),
                           error_category="analysis_error", request_id=request_id)
        raise HTTPException(status_code=503, detail="Security analysis unavailable") from None

    log_security_event("/secure-chat", request.prompt,
                       "allow" if result.allowed else "block",
                       round((time.perf_counter() - start) * 1000, 2),
                       layer=layer, score=float(result.risk_score), request_id=request_id)

    if not result.allowed:
        return ChatResponse(
            allowed=False,
            risk_score=result.risk_score,
            primary_threat=result.primary_threat,
            triggered_rules=result.triggered_rules,
            detector_results=result.detector_results,
            blocking_detector=result.blocking_detector,
            response=None,
            message=f"Request blocked. Detected threat: {result.primary_threat}",
        )

    try:
        llm_response = call_llm(request.prompt)
    except Exception:
        log_security_event("/secure-chat", request.prompt, "error",
                           round((time.perf_counter() - start) * 1000, 2),
                           error_category="provider_error", request_id=request_id)
        raise HTTPException(status_code=502, detail="Generation unavailable") from None

    return ChatResponse(
        allowed=True,
        risk_score=result.risk_score,
        primary_threat=result.primary_threat,
        triggered_rules=result.triggered_rules,
        detector_results=result.detector_results,
        blocking_detector=None,
        response=llm_response,
        message="Request allowed.",
    )
