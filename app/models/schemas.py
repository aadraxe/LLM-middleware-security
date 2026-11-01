from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Literal


class ChatRequest(BaseModel):
    prompt: str
    conversation_history: Optional[List[str]] = []  # prior prompts for multi-turn detection


class DetectionResult(BaseModel):
    """Result from a single detector."""
    allowed: bool
    risk_score: float
    threat_type: Optional[str] = None
    triggered_rules: List[str] = []
    detection_layer: Optional[str] = None
    layer_scores: Optional[Dict[str, float]] = {}


class PipelineResult(BaseModel):
    """Aggregated result from running all detectors in the pipeline."""
    allowed: bool
    risk_score: float                         # highest risk score across all detectors
    primary_threat: Optional[str] = None      # threat type of the highest-scoring detector
    triggered_rules: List[str] = []           # all triggered rules across detectors
    detector_results: Dict[str, dict] = {}    # per-detector full breakdown
    blocking_detector: Optional[str] = None   # which detector caused the block


class ChatResponse(BaseModel):
    allowed: bool
    risk_score: float
    primary_threat: Optional[str] = None
    triggered_rules: List[str] = []
    detector_results: Dict[str, dict] = {}
    blocking_detector: Optional[str] = None
    response: Optional[str] = None
    message: str


class CheckRequest(BaseModel):
    """POST /v1/check request: one piece of text to screen."""
    text: str = Field(min_length=1, max_length=100_000)
    source: Literal["user", "rag"] = "user"   # where the text came from (logged)


class CheckResponse(BaseModel):
    """POST /v1/check response."""
    verdict: Literal["allow", "block"]
    score: float                               # pipeline risk score, 0–1
    layer: Literal["rules", "fuzzy", "classifier", "judge"]  # stage that decided
    latency_ms: float                          # gateway processing time
