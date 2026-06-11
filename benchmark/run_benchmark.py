"""
run_benchmark.py
Benchmark the threat detection pipeline against a labeled dataset.

Measures: detection rate (recall), false positive rate, precision, F1, accuracy.

Usage:
    python benchmark/run_benchmark.py                  # uses deepset/prompt-injections
    python benchmark/run_benchmark.py --sample          # uses local sample (offline)
"""

import sys
import os
import argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.detectors.pipeline import ThreatPipeline


def load_data(use_sample: bool, subset: int = 0):
    """Returns a list of (text, true_label) where label is 1=attack, 0=benign."""
    if use_sample:
        import json
        path = os.path.join(os.path.dirname(__file__), "sample_data.json")
        with open(path) as f:
            rows = json.load(f)
        data = [(r["text"], r["label"]) for r in rows]
    else:
        from datasets import load_dataset
        ds = load_dataset("deepset/prompt-injections")
        data = []
        for split in ds.keys():
            for r in ds[split]:
                data.append((r["text"], int(r["label"])))

    # If a subset size is requested, take a reproducible random sample
    if subset and subset < len(data):
        import random
        random.seed(42)  # fixed seed = same sample every run = reproducible
        data = random.sample(data, subset)

    return data


def evaluate(data):
    """
    Run every prompt through the pipeline and compute metrics.

    The pipeline returns a PipelineResult. result.allowed == False means
    the pipeline flagged it as an ATTACK (predicted label = 1).

    ───────────────────────────────────────────────────────────────
    YOUR PART — fill in the four counters below.

    For each (text, true_label):
      - run the pipeline:           result = pipeline.analyze(text)
      - prediction = 1 if the pipeline BLOCKED it, else 0
      - compare prediction vs true_label and increment:
          tp  true positive   (attack correctly blocked)
          fp  false positive   (benign wrongly blocked)
          tn  true negative   (benign correctly allowed)
          fn  false negative   (attack wrongly allowed)
    ───────────────────────────────────────────────────────────────
    """
    pipeline = ThreatPipeline()
    tp = fp = tn = fn = 0

    for text, true_label in data:
        # Run the prompt through all detectors in the pipeline
        result = pipeline.analyze(text)

        # The pipeline BLOCKS attacks. So if allowed == False, the pipeline
        # is predicting "this is an attack" (label 1). If allowed == True,
        # it predicts "benign" (label 0).
        prediction = 0 if result.allowed else 1

        # Compare our prediction against the dataset's true label and tally
        # into the confusion-matrix buckets.
        if prediction == 1 and true_label == 1:
            tp += 1   # attack, and we caught it
        elif prediction == 1 and true_label == 0:
            fp += 1   # benign, but we wrongly blocked it
        elif prediction == 0 and true_label == 0:
            tn += 1   # benign, and we correctly let it through
        else:  # prediction == 0 and true_label == 1
            fn += 1   # attack, but we missed it

    return tp, fp, tn, fn


def report(tp, fp, tn, fn):
    """
    YOUR PART — compute the metrics from the four counters.

    Formulas:
      precision        = tp / (tp + fp)
      recall (detect)  = tp / (tp + fn)
      false_pos_rate   = fp / (fp + tn)
      accuracy         = (tp + tn) / total
      f1               = 2 * precision * recall / (precision + recall)

    Guard against division by zero (return 0.0 if denominator is 0).
    """
    total = tp + fp + tn + fn

    # Precision: of everything we BLOCKED, how much was actually an attack?
    # High precision = few false alarms.
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    # Recall / detection rate: of all REAL attacks, how many did we catch?
    # High recall = few attacks slip through.
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # False positive rate: of all BENIGN prompts, how many did we wrongly block?
    # This is the "annoying the user" metric — you want it low.
    false_pos_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Accuracy: overall, what fraction did we get right? (less useful when
    # classes are imbalanced, but good to show alongside the others.)
    accuracy = (tp + tn) / total if total > 0 else 0.0

    # F1: harmonic mean of precision and recall — a single number that
    # balances "catching attacks" against "not over-blocking."
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print("=" * 50)
    print("  THREAT PIPELINE BENCHMARK RESULTS")
    print("=" * 50)
    print(f"  Total prompts:        {total}")
    print(f"  True Positives  (TP): {tp}   (attacks caught)")
    print(f"  False Positives (FP): {fp}   (benign wrongly blocked)")
    print(f"  True Negatives  (TN): {tn}   (benign allowed)")
    print(f"  False Negatives (FN): {fn}   (attacks missed)")
    print("-" * 50)
    print(f"  Detection rate (recall): {recall:.1%}")
    print(f"  False positive rate:     {false_pos_rate:.1%}")
    print(f"  Precision:               {precision:.1%}")
    print(f"  Accuracy:                {accuracy:.1%}")
    print(f"  F1 score:                {f1:.3f}")
    print("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", action="store_true", help="use local offline sample")
    parser.add_argument("--subset", type=int, default=0, help="randomly sample N prompts")
    args = parser.parse_args()

    print("Loading data...")
    data = load_data(args.sample, args.subset)
    print(f"Loaded {len(data)} prompts. Running pipeline (this may take a bit)...\n")

    tp, fp, tn, fn = evaluate(data)
    report(tp, fp, tn, fn)
