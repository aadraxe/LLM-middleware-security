"""
pipeline.py
Unified threat detection pipeline.

Runs every registered detector against a prompt, aggregates the results,
and decides allow/block based on the highest-risk detector. Designed so
new detectors (PII, harmful content, etc.) can be added with one line.
"""

import os
from typing import Optional, List
from app.detectors.base import BaseDetector
from app.detectors.jailbreak_detector import JailbreakDetector
from app.detectors.prompt_injection_detector import PromptInjectionDetector
from app.models.schemas import PipelineResult


class ThreatPipeline:
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        # Register detectors here. Order doesn't matter — all run, highest risk wins.
        self.detectors: List[BaseDetector] = detectors or [
            JailbreakDetector(),
            PromptInjectionDetector(),
        ]

    def analyze(self, prompt: str, conversation_history: Optional[list] = None) -> PipelineResult:
        detector_results: dict = {}
        all_triggered: list = []
        highest_score = 0.0
        primary_threat = None
        blocking_detector = None
        blocked = False

        for detector in self.detectors:
            result = detector.detect(prompt, conversation_history)

            detector_results[detector.name] = {
                "allowed": result.allowed,
                "risk_score": result.risk_score,
                "threat_type": result.threat_type,
                "triggered_rules": result.triggered_rules,
                "detection_layer": result.detection_layer,
                "layer_scores": result.layer_scores,
            }

            # Collect triggered rules (prefixed with detector name for clarity)
            for rule in result.triggered_rules:
                all_triggered.append(f"{detector.threat_type}:{rule}")

            # Track the highest-risk detector
            if result.risk_score > highest_score:
                highest_score = result.risk_score
                primary_threat = result.threat_type or primary_threat

            # If any detector blocks, the whole pipeline blocks
            if not result.allowed:
                blocked = True
                # The blocking detector is the highest-scoring one that blocked
                if blocking_detector is None or result.risk_score >= highest_score:
                    blocking_detector = detector.name
                    primary_threat = result.threat_type

        return PipelineResult(
            allowed=not blocked,
            risk_score=round(highest_score, 3),
            primary_threat=primary_threat,
            triggered_rules=all_triggered,
            detector_results=detector_results,
            blocking_detector=blocking_detector,
        )


CLASSIFIER_BACKENDS = ("llama", "local", "both", "none")


def build_pipeline(backend: Optional[str] = None, local_detector: Optional[BaseDetector] = None) -> ThreatPipeline:
    """
    Build the pipeline for a classifier backend (default: CLASSIFIER_BACKEND env var, else "llama").

      llama — regex + fuzzy + Llama 3.3 judge (original behaviour)
      local — regex + fuzzy + local fine-tuned classifier, no API calls
      both  — regex + fuzzy + Llama judge + local classifier
      none  — regex + fuzzy only
    """
    backend = (backend or os.environ.get("CLASSIFIER_BACKEND", "llama")).lower()
    if backend not in CLASSIFIER_BACKENDS:
        raise ValueError(f"CLASSIFIER_BACKEND must be one of {CLASSIFIER_BACKENDS}, got {backend!r}")

    use_llm = backend in ("llama", "both")
    detectors: List[BaseDetector] = [
        JailbreakDetector(use_llm_judge=use_llm),
        PromptInjectionDetector(use_llm_judge=use_llm),
    ]
    if backend in ("local", "both"):
        if local_detector is None:
            from app.detectors.finetuned_detector import FineTunedDetector
            local_detector = FineTunedDetector()
        detectors.append(local_detector)
    return ThreatPipeline(detectors)


# Singleton instance used by the app
pipeline = build_pipeline()
