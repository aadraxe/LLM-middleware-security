from pydantic import BaseModel
from typing import Optional, List


class ChatRequest(BaseModel):
    prompt: str


class DetectionResult(BaseModel):
    allowed: bool
    risk_score: float
    threat_type: Optional[str] = None
    triggered_rules: List[str] = []


class ChatResponse(BaseModel):
    allowed: bool
    risk_score: float
    threat_type: Optional[str] = None
    triggered_rules: List[str] = []
    response: Optional[str] = None
    message: str