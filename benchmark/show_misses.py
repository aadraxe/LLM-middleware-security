"""
show_misses.py
Diagnostic: print the attacks the pipeline MISSED (false negatives)
and the benign prompts it WRONGLY BLOCKED (false positives).

This is how you find out WHERE your detection is weak, instead of guessing.

Usage:
    python benchmark/show_misses.py
    python benchmark/show_misses.py --sample
    python benchmark/show_misses.py --limit 30
"""

import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.detectors.pipeline import ThreatPipeline


def load_data(use_sample: bool):
    if use_sample:
        import json
        with open(os.path.join(os.path.dirname(__file__), "sample_data.json")) as f:
            return [(r["text"], r["label"]) for r in json.load(f)]
    from datasets import load_dataset
    ds = load_dataset("deepset/prompt-injections")
    rows = []
    for split in ds.keys():
        for r in ds[split]:
            rows.append((r["text"], int(r["label"])))
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", action="store_true")
    parser.add_argument("--limit", type=int, default=15, help="how many to show")
    args = parser.parse_args()

    pipeline = ThreatPipeline()
    data = load_data(args.sample)

    false_negatives = []  # attacks we missed
    false_positives = []  # benign we wrongly blocked

    for text, true_label in data:
        result = pipeline.analyze(text)
        prediction = 0 if result.allowed else 1
        if prediction == 0 and true_label == 1:
            false_negatives.append(text)
        elif prediction == 1 and true_label == 0:
            false_positives.append(text)

    print("\n" + "=" * 70)
    print(f"  MISSED ATTACKS (false negatives): {len(false_negatives)} total")
    print(f"  Showing first {args.limit}")
    print("=" * 70)
    for i, text in enumerate(false_negatives[:args.limit], 1):
        snippet = text.replace("\n", " ")[:200]
        print(f"\n  [{i}] {snippet}")

    print("\n" + "=" * 70)
    print(f"  WRONGLY BLOCKED (false positives): {len(false_positives)} total")
    print("=" * 70)
    for i, text in enumerate(false_positives[:args.limit], 1):
        snippet = text.replace("\n", " ")[:200]
        print(f"\n  [{i}] {snippet}")
    print()