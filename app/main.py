from fastapi import FastAPI
from datetime import datetime
import json
import os

from app.models.schemas import ChatRequest, ChatResponse
from app.detectors.pipeline import pipeline
from app.services.llm_service import call_llm


app = FastAPI(
    title="Secure LLM Gateway",
    description="Multi-layer middleware detecting jailbreaks and prompt injection before prompts reach an LLM.",
    version="0.3.0",
)

LOG_FILE = "app/logs/security_events.jsonl"


def log_event(event: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


@app.get("/")
def root():
    return {
        "message": "Secure LLM Gateway is running",
        "version": "0.3.0",
        "detectors": [d.name for d in pipeline.detectors],
    }


@app.post("/secure-chat", response_model=ChatResponse)
def secure_chat(request: ChatRequest):
    result = pipeline.analyze(
        request.prompt,
        conversation_history=request.conversation_history,
    )

    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "prompt": request.prompt,
        "allowed": result.allowed,
        "risk_score": result.risk_score,
        "primary_threat": result.primary_threat,
        "blocking_detector": result.blocking_detector,
        "triggered_rules": result.triggered_rules,
        "detector_results": result.detector_results,
    }
    log_event(event)

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

    llm_response = call_llm(request.prompt)

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
