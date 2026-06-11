"""
base.py
Abstract base class for all threat detectors in the pipeline.
Each detector takes a prompt (+ optional history) and returns a DetectionResult.
"""

from abc import ABC, abstractmethod
from typing import Optional
from app.models.schemas import DetectionResult


class BaseDetector(ABC):
    # Each detector declares its threat type and block threshold
    threat_type: str = "unknown"
    block_threshold: float = 0.70

    @abstractmethod
    def detect(self, prompt: str, conversation_history: Optional[list] = None) -> DetectionResult:
        """Analyze a prompt and return a DetectionResult."""
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self.__class__.__name__
