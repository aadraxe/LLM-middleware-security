"""
finetuned_detector.py
Local fine-tuned prompt-injection / jailbreak classifier.

Runs a small encoder model (trained by classifier/train.py) on CPU, so the
prompt never leaves the machine and no API call is needed. torch and
transformers are imported lazily: the default gateway (Llama judge) does not
need them installed.

Model directory layout (written by classifier/train.py):
    config.json, model weights, tokenizer files
    threshold.json   {"threshold": 0.xx}  — chosen on the validation set
"""

import json
import os
from typing import Optional, List

from app.detectors.base import BaseDetector
from app.models.schemas import DetectionResult

DEFAULT_MODEL_DIR = os.environ.get("LOCAL_CLASSIFIER_PATH", "models/finetuned-classifier")


class FineTunedClassifier:
    """Thin inference wrapper: text(s) in, attack probability out."""

    def __init__(self, model_dir: str = DEFAULT_MODEL_DIR, max_length: int = 256,
                 threshold: Optional[float] = None):
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        self.torch = torch
        self.model_dir = model_dir
        self.max_length = max_length
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        self.model.eval()

        if threshold is None:
            path = os.path.join(model_dir, "threshold.json")
            threshold = json.load(open(path))["threshold"] if os.path.exists(path) else 0.5
        self.threshold = threshold

    def predict_proba(self, texts: List[str], batch_size: int = 16) -> List[float]:
        probs: List[float] = []
        with self.torch.no_grad():
            for i in range(0, len(texts), batch_size):
                enc = self.tokenizer(texts[i:i + batch_size], truncation=True,
                                     max_length=self.max_length, padding=True,
                                     return_tensors="pt")
                logits = self.model(**enc).logits
                probs.extend(self.torch.softmax(logits, dim=-1)[:, 1].tolist())
        return probs


class FineTunedDetector(BaseDetector):
    """Pipeline stage wrapping FineTunedClassifier. Blocks when the attack
    probability is at or above the validation-chosen threshold."""

    threat_type = "prompt_attack"

    def __init__(self, classifier: Optional[FineTunedClassifier] = None,
                 model_dir: str = DEFAULT_MODEL_DIR):
        self.classifier = classifier or FineTunedClassifier(model_dir)
        self.block_threshold = self.classifier.threshold

    def detect(self, prompt: str, conversation_history: Optional[list] = None) -> DetectionResult:
        prob = self.classifier.predict_proba([prompt])[0]
        blocked = prob >= self.block_threshold
        return DetectionResult(
            allowed=not blocked,
            risk_score=round(prob, 3),
            threat_type=self.threat_type if blocked else None,
            triggered_rules=[f"finetuned_classifier: p_attack={prob:.3f}"] if blocked else [],
            detection_layer="finetuned_classifier",
            layer_scores={"finetuned_classifier": round(prob, 3)},
        )
