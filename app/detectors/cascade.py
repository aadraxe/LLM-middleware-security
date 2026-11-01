"""
cascade.py
Tiered pipeline modes built on the fine-tuned classifier and the rule split.

  local_only — block if a blocking rule fires or the classifier score is at or
               above its threshold. No API calls; signal rules are ignored.
  cascade    — route on the classifier score s (see route()):
                 blocking rule fired          → block
                 s >= HIGH                    → block
                 LOW < s < HIGH, or a signal
                 rule fired                   → ask the LLM judge
                 otherwise (s <= LOW)         → allow

Thresholds, the band and the rule split are read from cascade_config.json,
which benchmark/eval_cascade.py writes from the VALIDATION set only.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from app.models.schemas import PipelineResult

DEFAULT_CONFIG_PATH = os.environ.get(
    "CASCADE_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "cascade_config.json"))

BLOCK, ALLOW, JUDGE = "block", "allow", "judge"
# Reasons llm_judge() returns when no verdict was obtained (it fails open)
JUDGE_FAILURE_PREFIXES = ("LLM judge skipped", "LLM judge unavailable", "no choices")


@dataclass
class CascadeConfig:
    threshold: float
    low: float
    high: float
    blocking_rules: List[str] = field(default_factory=list)
    signal_rules: List[str] = field(default_factory=list)
    model_dir: Optional[str] = None

    @classmethod
    def load(cls, path: str = DEFAULT_CONFIG_PATH) -> "CascadeConfig":
        with open(path) as f:
            c = json.load(f)
        return cls(threshold=c["threshold"], low=c["low"], high=c["high"],
                   blocking_rules=c["blocking_rules"], signal_rules=c["signal_rules"],
                   model_dir=c.get("model_dir"))


def route(score: float, fired: List[str], cfg: CascadeConfig) -> Tuple[str, str]:
    """Cascade decision for one prompt: (BLOCK | ALLOW | JUDGE, reason)."""
    blocking = [r for r in fired if r in cfg.blocking_rules]
    if blocking:
        return BLOCK, f"blocking rule: {blocking[0]}"
    if score >= cfg.high:
        return BLOCK, f"classifier score {score:.3f} >= HIGH {cfg.high}"
    signals = [r for r in fired if r in cfg.signal_rules]
    if signals:
        return JUDGE, f"signal rule: {signals[0]}"
    if score > cfg.low:
        return JUDGE, f"classifier score {score:.3f} in band ({cfg.low}, {cfg.high})"
    return ALLOW, f"classifier score {score:.3f} <= LOW {cfg.low}"


def local_only_decision(score: float, fired: List[str], cfg: CascadeConfig) -> Tuple[str, str]:
    blocking = [r for r in fired if r in cfg.blocking_rules]
    if blocking:
        return BLOCK, f"blocking rule: {blocking[0]}"
    if score >= cfg.threshold:
        return BLOCK, f"classifier score {score:.3f} >= threshold {cfg.threshold}"
    return ALLOW, f"classifier score {score:.3f} < threshold {cfg.threshold}"


class _Stage:
    """Named placeholder so the gateway's root endpoint can list the stages."""
    def __init__(self, name):
        self.name = name


class TieredPipeline:
    def __init__(self, mode: str, cfg: Optional[CascadeConfig] = None, classifier=None,
                 judge: Optional[Callable[[str], Tuple[bool, float, str]]] = None,
                 rule_fn: Optional[Callable] = None):
        if mode not in ("local_only", "cascade"):
            raise ValueError(f"TieredPipeline mode must be local_only or cascade, got {mode!r}")
        self.mode = mode
        self.cfg = cfg or CascadeConfig.load()
        if classifier is None:
            from app.detectors.finetuned_detector import FineTunedClassifier, DEFAULT_MODEL_DIR
            model_dir = os.environ.get("LOCAL_CLASSIFIER_PATH") or self.cfg.model_dir or DEFAULT_MODEL_DIR
            classifier = FineTunedClassifier(model_dir, threshold=self.cfg.threshold)
        self.classifier = classifier
        if rule_fn is None:
            from app.detectors.rules import rule_hits as rule_fn
        self.rule_fn = rule_fn
        if judge is None and mode == "cascade":
            from app.detectors.jailbreak_detector import llm_judge as judge
        self.judge = judge
        stages = ["RuleScreen", "FineTunedClassifier"] + (["LLMJudge"] if mode == "cascade" else [])
        self.detectors = [_Stage(n) for n in stages]

    def analyze(self, prompt: str, conversation_history: Optional[list] = None) -> PipelineResult:
        fired = self.rule_fn(prompt, conversation_history)
        score = self.classifier.predict_proba([prompt])[0]
        decide = route if self.mode == "cascade" else local_only_decision
        decision, reason = decide(score, fired, self.cfg)
        layer = "rules" if reason.startswith("blocking rule") else "finetuned_classifier"
        details = {"mode": self.mode, "classifier_score": round(score, 3), "rules_fired": fired,
                   "route": decision, "reason": reason}

        if decision == JUDGE:
            is_attack, confidence, judge_reason = self.judge(prompt)
            if judge_reason.startswith(JUDGE_FAILURE_PREFIXES):
                # No verdict: fall back to the classifier's own threshold
                is_attack = score >= self.cfg.threshold
                judge_reason = f"judge unavailable, classifier fallback ({judge_reason})"
            details.update(judge_attack=is_attack, judge_confidence=confidence, judge_reason=judge_reason)
            decision = BLOCK if is_attack else ALLOW
            layer = "llm_judge"
            reason = f"{reason}; judge: {judge_reason}"

        blocked = decision == BLOCK
        return PipelineResult(
            allowed=not blocked,
            risk_score=round(score, 3),
            primary_threat="prompt_attack" if blocked else None,
            triggered_rules=[f"rule:{r}" for r in fired] + ([reason] if blocked else []),
            detector_results={"TieredPipeline": {**details, "detection_layer": layer}},
            blocking_detector=f"TieredPipeline:{layer}" if blocked else None,
        )
