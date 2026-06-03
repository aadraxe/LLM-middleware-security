from fastapi import FastAPI
from datetime import datetime
import json
import os

from app.models.schemas import ChatRequest, ChatResponse
from app.detectors.jailbreak_detector import detect_jailbreak
from app.services.llm_service import call_llm


app = FastAPI(
    title="Secure LLM Gateway",
    description="Multi-layer middleware for detecting jailbreak attempts before prompts reach an LLM.",
    version="0.2.0",
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
        "version": "0.2.0",
        "detection_layers": ["regex", "fuzzy", "llm_judge"],
    }


@app.post("/secure-chat", response_model=ChatResponse)
def secure_chat(request: ChatRequest):
    detection = detect_jailbreak(
        request.prompt,
        conversation_history=request.conversation_history,
    )

    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "prompt": request.prompt,
        "allowed": detection.allowed,
        "risk_score": detection.risk_score,
        "threat_type": detection.threat_type,
        "triggered_rules": detection.triggered_rules,
        "detection_layer": detection.detection_layer,
        "layer_scores": detection.layer_scores,
    }
    log_event(event)

    if not detection.allowed:
        return ChatResponse(
            allowed=False,
            risk_score=detection.risk_score,
            threat_type=detection.threat_type,
            triggered_rules=detection.triggered_rules,
            detection_layer=detection.detection_layer,
            layer_scores=detection.layer_scores,
            response=None,
            message="Request blocked due to suspected jailbreak attempt.",
        )

    llm_response = call_llm(request.prompt)

    return ChatResponse(
        allowed=True,
        risk_score=detection.risk_score,
        threat_type=detection.threat_type,
        triggered_rules=detection.triggered_rules,
        detection_layer=detection.detection_layer,
        layer_scores=detection.layer_scores,
        response=llm_response,
        message="Request allowed.",
    )
