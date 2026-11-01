"""
metrics.py
Shared metric helpers for training and benchmarking, so every configuration
is scored with exactly the same formulas as benchmark/run_benchmark.py.
"""

import json


def confusion(labels, preds):
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    return tp, fp, tn, fn


def scores(labels, preds) -> dict:
    tp, fp, tn, fn = confusion(labels, preds)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n": len(labels), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": round(recall, 4), "precision": round(precision, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4), "accuracy": round(accuracy, 4),
    }


def choose_threshold(labels, probs) -> float:
    """Pick the threshold that maximises F1 on the VALIDATION set.
    Ties go to the higher threshold (fewer false alarms)."""
    best_t, best_f1 = 0.5, -1.0
    for i in range(5, 100):
        t = i / 100
        f1 = scores(labels, [int(p >= t) for p in probs])["f1"]
        if f1 >= best_f1:
            best_t, best_f1 = t, f1
    return best_t


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]
