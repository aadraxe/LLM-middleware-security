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

      llama — regex + fuzzy + LLM judge (original pipeline; the judge is now gpt-oss-120b)
      local — regex + fuzzy + local fine-tuned classifier, no API calls
      both  — regex + fuzzy + LLM judge + local classifier
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


PIPELINE_MODES = ("local_only", "cascade", "full")
DEFAULT_PIPELINE_MODE = "local_only"


def resolve_pipeline_mode(mode: Optional[str] = None) -> str:
    """
    Which pipeline the gateway runs:
      explicit argument > PIPELINE_MODE > legacy CLASSIFIER_BACKEND > local_only.
    A legacy CLASSIFIER_BACKEND value is returned as "backend:<value>".
    """
    mode = mode or os.environ.get("PIPELINE_MODE")
    if mode:
        mode = mode.lower()
        if mode not in PIPELINE_MODES:
            raise ValueError(f"PIPELINE_MODE must be one of {PIPELINE_MODES}, got {mode!r}")
        return mode
    if os.environ.get("CLASSIFIER_BACKEND"):
        return f"backend:{os.environ['CLASSIFIER_BACKEND'].lower()}"
    return DEFAULT_PIPELINE_MODE


def build_gateway_pipeline(mode: Optional[str] = None):
    """
    Pipeline for the gateway, chosen by PIPELINE_MODE (default local_only):

      local_only — high-precision rules + fine-tuned classifier, no API calls
      cascade    — classifier decides confident cases; uncertain ones and
                   signal-rule hits go to the LLM judge
      full       — every stage: regex + fuzzy + LLM judge + classifier

    Setting the legacy CLASSIFIER_BACKEND (llama / local / both / none) still
    works when PIPELINE_MODE is unset.
    """
    mode = resolve_pipeline_mode(mode)
    if mode.startswith("backend:"):
        return build_pipeline(mode.split(":", 1)[1])
    if mode in ("local_only", "cascade", "full"):
        _require_local_model()
    if mode == "full":
        return build_pipeline("both")
    from app.detectors.cascade import TieredPipeline
    return TieredPipeline(mode)


def _require_local_model():
    from app.detectors.finetuned_detector import DEFAULT_MODEL_DIR
    model_dir = os.environ.get("LOCAL_CLASSIFIER_PATH") or DEFAULT_MODEL_DIR
    if not os.path.isdir(model_dir):
        raise RuntimeError(
            f"Fine-tuned classifier not found at {model_dir!r}. Train it with "
            "`python classifier/train.py --model distilbert-base-uncased --run-name distilbert`, "
            "point LOCAL_CLASSIFIER_PATH at a trained model, or set CLASSIFIER_BACKEND=llama "
            "to run the original regex + fuzzy + LLM judge pipeline without it.")
