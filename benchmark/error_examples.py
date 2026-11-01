"""
error_examples.py
Pull representative errors out of a compare_classifiers.py run, for the
error analysis in the README / model card.

Usage:
    python benchmark/error_examples.py results/comparison_distilbert
"""

import json
import os
import random
import sys


def snippet(text, n=160):
    t = " ".join(text.split())
    return t if len(t) <= n else t[:n] + "…"


def main(run_dir, per_bucket=5):
    rows = [json.loads(l) for l in open(os.path.join(run_dir, "rows.jsonl"), encoding="utf-8")]
    rng = random.Random(42)
    buckets = [
        ("Missed attacks on the deepset benchmark (all stages, config d)", "benchmark_200",
         lambda r: r["label"] == 1 and not r["pred"]["d_all_stages"]),
        ("Missed attacks on the held-out test set (fine-tuned model, config e)", "test_full",
         lambda r: r["label"] == 1 and not r["pred"]["e_finetuned_only"]),
        ("False alarms on the held-out test set from the fine-tuned model (config e)", "test_full",
         lambda r: r["label"] == 0 and r["pred"]["e_finetuned_only"]),
        ("False alarms on the held-out test set from regex + fuzzy rules (config a)", "test_full",
         lambda r: r["label"] == 0 and r["pred"]["a_regex_fuzzy"]),
    ]
    out = ["# Error examples", "",
           f"Sampled with seed 42 from `{os.path.relpath(run_dir)}/rows.jsonl`. "
           "`p` is the fine-tuned model's attack probability.", ""]
    for title, set_name, cond in buckets:
        hits = [r for r in rows if r["set"] == set_name and cond(r)]
        out += [f"## {title}: {len(hits)} total", "", "| p | source | prompt |", "|---|---|---|"]
        for r in rng.sample(hits, min(per_bucket, len(hits))):
            out.append(f"| {r['p_local']:.2f} | {r['source']} | {snippet(r['text']).replace('|', '/')} |")
        out.append("")
    path = os.path.join(run_dir, "errors.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results/comparison_distilbert")
