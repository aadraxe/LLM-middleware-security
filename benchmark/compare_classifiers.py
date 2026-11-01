"""
compare_classifiers.py
Compare gateway configurations on the same prompts:

  (a) regex + fuzzy only                     CLASSIFIER_BACKEND=none
  (b) regex + fuzzy + LLM judge              CLASSIFIER_BACKEND=llama
  (c) regex + fuzzy + fine-tuned classifier  CLASSIFIER_BACKEND=local
  (d) all stages                             CLASSIFIER_BACKEND=both
  (e) fine-tuned classifier alone            (reference row: the model with no rules)

Eval sets:
  benchmark_200  the original seeded 200-prompt deepset subset (all configs)
  test_300       a seeded 300-prompt sample of the held-out test split (all configs;
                 sampled because the Groq free tier caps daily requests/tokens)
  test_full      the full held-out test split (a, c and e only, no API calls)

Latency is per prompt, measured on this machine:
  a, c  wall-clock time of the real pipeline call
  b     time of (a) + the recorded latency of the original (uncached) judge call(s)
  d     time of (b) + the fine-tuned stage's own time (stages run sequentially)
  e     wall-clock time of the fine-tuned stage alone

Judge verdicts are cached in benchmark/judge_cache/ so re-runs cost nothing.
If a judge call fails (e.g. the daily quota runs out) the run stops instead of
silently counting the failure as "allowed". Re-run later to resume from cache.

Usage:
    python benchmark/compare_classifiers.py --model-dir models/distilbert
"""

import argparse
import json
import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("JUDGE_CACHE_DIR", os.path.join(ROOT, "benchmark", "judge_cache"))
# The earlier run used Groq's default temperature; keep it so these results reproduce.
os.environ.setdefault("JUDGE_TEMPERATURE", "default")

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
except ImportError:
    pass

import app.detectors.judge_cache as judge_cache
from app.detectors.pipeline import build_pipeline
from app.detectors.finetuned_detector import FineTunedDetector
from classifier.metrics import scores, load_jsonl

DATA = os.path.join(ROOT, "data", "processed")
CONFIGS = ["a_regex_fuzzy", "b_regex_fuzzy_llm", "c_regex_fuzzy_finetuned", "d_all_stages", "e_finetuned_only"]
NO_LLM_CONFIGS = ["a_regex_fuzzy", "c_regex_fuzzy_finetuned", "e_finetuned_only"]

# Record every judge call so latency is real and failures are never silent
_calls = []
_real_judge_request = judge_cache.judge_request


def _recording_judge_request(*args, **kwargs):
    # SystemExit is not an Exception, so the detectors' `except Exception`
    # fallback (which would count a failure as "allowed") can't swallow it.
    try:
        data = _real_judge_request(*args, **kwargs)
    except judge_cache.DailyLimitReached as e:
        raise SystemExit(f"Groq daily limit reached: {e}\n"
                         "Verdicts so far are cached; re-run later to resume.")
    if "choices" not in data:
        raise SystemExit(f"Judge call failed ({data.get('_status')}): "
                         f"{str(data.get('error', data))[:200]}\nRe-run later to resume from cache.")
    _calls.append(data.get("_latency_ms", 0.0))
    return data


judge_cache.judge_request = _recording_judge_request


def timed(fn, *args):
    start = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - start) * 1000


def run_set(rows, pipes, local, use_llm, label):
    out = []
    for i, r in enumerate(rows):
        text = r["text"]
        ra, la = timed(pipes["none"].analyze, text)
        rc, lc = timed(pipes["local"].analyze, text)
        rl, ll = timed(local.detect, text)
        rec = {
            "text": text, "label": r["label"], "source": r.get("source"),
            "p_local": rl.risk_score,
            "pred": {"a_regex_fuzzy": int(not ra.allowed), "c_regex_fuzzy_finetuned": int(not rc.allowed),
                     "e_finetuned_only": int(not rl.allowed)},
            "latency_ms": {"a_regex_fuzzy": la, "c_regex_fuzzy_finetuned": lc, "e_finetuned_only": ll},
        }
        if use_llm:
            _calls.clear()
            rb = pipes["llama"].analyze(text)
            lb = la + sum(_calls)
            rec["n_judge_calls"] = len(_calls)
            rec["pred"]["b_regex_fuzzy_llm"] = int(not rb.allowed)
            rec["pred"]["d_all_stages"] = int((not rb.allowed) or (not rl.allowed))
            rec["latency_ms"]["b_regex_fuzzy_llm"] = lb
            rec["latency_ms"]["d_all_stages"] = lb + ll
        out.append(rec)
        if (i + 1) % 25 == 0:
            print(f"  {label}: {i+1}/{len(rows)}", flush=True)
    return out


def summarize(recs, configs):
    res = {}
    for c in configs:
        m = scores([r["label"] for r in recs], [r["pred"][c] for r in recs])
        lat = [r["latency_ms"][c] for r in recs]
        m["latency_ms_mean"] = round(sum(lat) / len(lat), 2)
        m["latency_ms_p95"] = round(sorted(lat)[int(len(lat) * 0.95)], 2)
        res[c] = m
    return res


def markdown(results, model_dir, threshold):
    lines = [f"Fine-tuned model: `{os.path.relpath(model_dir, ROOT)}` (threshold {threshold}, chosen on validation)",
             f"LLM judge: `{judge_cache.JUDGE_MODEL}` via Groq", ""]
    for set_name, res in results.items():
        n = next(iter(res.values()))["n"]
        lines += [f"### {set_name} (n={n})", "",
                  "| Config | Recall | Precision | F1 | FPR | Mean latency (ms) | p95 latency (ms) |",
                  "|---|---|---|---|---|---|---|"]
        for c, m in res.items():
            lines.append(f"| {c} | {m['recall']:.1%} | {m['precision']:.1%} | {m['f1']:.3f} | "
                         f"{m['fpr']:.1%} | {m['latency_ms_mean']:.1f} | {m['latency_ms_p95']:.1f} |")
        lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--test-sample", type=int, default=300)
    ap.add_argument("--skip-llm", action="store_true", help="only configs a and c")
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "results", "comparison"))
    ap.add_argument("--force", action="store_true", help="overwrite an existing comparison")
    ap.add_argument("--warm-judge-cache", action="store_true",
                    help="only run the LLM judge over the eval sets to fill the cache")
    args = ap.parse_args()

    if args.warm_judge_cache:
        llama = build_pipeline("llama")
        test = load_jsonl(os.path.join(DATA, "test.jsonl"))
        rows = (load_jsonl(os.path.join(DATA, "benchmark_200.jsonl"))
                + random.Random(42).sample(test, min(args.test_sample, len(test))))
        for i, r in enumerate(rows):
            llama.analyze(r["text"])
            if (i + 1) % 25 == 0:
                print(f"  judged {i+1}/{len(rows)}", flush=True)
        print("judge cache warm")
        return

    if os.path.exists(os.path.join(args.out_dir, "comparison.json")) and not args.force:
        raise SystemExit(f"{args.out_dir} already has results; pass --force or choose --out-dir")
    if not args.skip_llm and not os.environ.get("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY not set (put it in .env) or pass --skip-llm")

    local = FineTunedDetector(model_dir=args.model_dir)
    local.detect("warm-up")
    pipes = {"none": build_pipeline("none"), "local": build_pipeline("local", local_detector=local),
             "llama": build_pipeline("llama")}

    bench = load_jsonl(os.path.join(DATA, "benchmark_200.jsonl"))
    test = load_jsonl(os.path.join(DATA, "test.jsonl"))
    test_300 = random.Random(42).sample(test, min(args.test_sample, len(test)))
    use_llm = not args.skip_llm
    configs = CONFIGS if use_llm else NO_LLM_CONFIGS

    print("benchmark_200 ...")
    bench_recs = run_set(bench, pipes, local, use_llm, "benchmark_200")
    print("test_300 ...")
    t300_recs = run_set(test_300, pipes, local, use_llm, "test_300")
    print("test_full (no LLM) ...")
    full_recs = run_set(test, pipes, local, False, "test_full")

    results = {
        "benchmark_200": summarize(bench_recs, configs),
        f"test_{len(test_300)}": summarize(t300_recs, configs),
        "test_full": summarize(full_recs, NO_LLM_CONFIGS),
    }

    os.makedirs(args.out_dir, exist_ok=True)
    meta = {"model_dir": os.path.relpath(args.model_dir, ROOT), "threshold": local.block_threshold,
            "judge_model": judge_cache.JUDGE_MODEL, "results": results}
    with open(os.path.join(args.out_dir, "comparison.json"), "w") as f:
        json.dump(meta, f, indent=2)
    with open(os.path.join(args.out_dir, "comparison.md"), "w", encoding="utf-8") as f:
        f.write(markdown(results, args.model_dir, local.block_threshold))
    with open(os.path.join(args.out_dir, "rows.jsonl"), "w", encoding="utf-8") as f:
        for set_name, recs in [("benchmark_200", bench_recs), ("test_300", t300_recs), ("test_full", full_recs)]:
            for r in recs:
                f.write(json.dumps({"set": set_name, **r}, ensure_ascii=False) + "\n")
    print(markdown(results, args.model_dir, local.block_threshold))


if __name__ == "__main__":
    main()
