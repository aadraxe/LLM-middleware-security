from pydantic import BaseModel
from typing import Optional, List, Dict


class ChatRequest(BaseModel):
    prompt: str
    conversation_history: Optional[List[str]] = []  # prior prompts for multi-turn detection


class DetectionResult(BaseModel):
    allowed: bool
    risk_score: float
    threat_type: Optional[str] = None
    triggered_rules: List[str] = []
    detection_layer: Optional[str] = None   # "regex" | "fuzzy" | "fuzzy_multi_turn" | "llm_judge"
    layer_scores: Optional[Dict[str, float]] = {}  # per-layer scores for audit


class ChatResponse(BaseModel):
    allowed: bool
    risk_score: float
    threat_type: Optional[str] = None
    triggered_rules: List[str] = []
    detection_layer: Optional[str] = None
    layer_scores: Optional[Dict[str, float]] = {}
    response: Optional[str] = None
    message: str
