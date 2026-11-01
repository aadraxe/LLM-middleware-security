"""
eval_cascade.py
Rule split, judge-alone baseline and classifier→judge cascade, end to end:

    python benchmark/eval_cascade.py              # everything (resumes from the judge cache)
    python benchmark/eval_cascade.py --no-judge   # selection on validation only, no API calls

1. SELECT (validation set only, no judge calls)
   - per-rule hits / precision → blocking vs signal rules         rule_stats.csv
   - LOW/HIGH band sweep for the cascade                            band_sweep.csv
   - writes app/detectors/cascade_config.json for the gateway
2. JUDGE (openai/gpt-oss-120b, temperature 0, cached in benchmark/judge_cache_t0.jsonl)
   - one verdict per prompt on test_300 + deepset_200, with the same template
     the jailbreak detector uses; the cascade reuses these verdicts
   - the old all-stages pipeline (d) for reference, which can also call the
     injection template on borderline prompts
   If Groq's daily quota runs out, progress is already on disk; the script
   prints how many prompts are left and exits. Re-run to resume.
3. EVALUATE on test_300 and deepset_200 (all configs) and test_full (no-judge configs)
   (e) fine-tuned alone         (f) judge alone
   (g) fine-tuned + blocking rules only   (h) cascade   (d) old all stages
   with 95% bootstrap CIs (1,000 resamples, seed 42), latency, judge usage,
   and a deepset breakdown by language.                             comparison.csv
   language_breakdown.csv, errors_best.csv, rows.jsonl, summary.md

Every threshold, rule decision and band comes from the validation set. The test
set and deepset are only scored.
"""

import argparse
import csv
import json
import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("JUDGE_CACHE_JSONL", os.path.join(ROOT, "benchmark", "judge_cache_t0.jsonl"))
os.environ.setdefault("JUDGE_TEMPERATURE", "0")
os.environ.pop("JUDGE_CACHE_DIR", None)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
except ImportError:
    pass

import numpy as np

import app.detectors.judge_cache as judge_cache
from app.detectors import jailbreak_detector
from app.detectors.cascade import CascadeConfig, route, local_only_decision, JUDGE, BLOCK, JUDGE_FAILURE_PREFIXES
from app.detectors.finetuned_detector import FineTunedClassifier
from app.detectors.pipeline import build_pipeline
from app.detectors.rules import rule_hits, all_rule_names, split_rules
from classifier.metrics import scores, load_jsonl

DATA = os.path.join(ROOT, "data", "processed")
OUT = os.path.join(ROOT, "results", "eval_cascade")
CONFIG_PATH = os.path.join(ROOT, "app", "detectors", "cascade_config.json")
SEED = 42
MIN_PRECISION, MIN_HITS = 0.95, 10
BAND_MIN_OUTSIDE_ACC, BAND_MAX_COVERAGE = 0.97, 0.25

CONFIGS = {
    "e_finetuned_only": "(e) fine-tuned alone",
    "f_judge_only": "(f) judge alone",
    "g_finetuned_blocking_rules": "(g) fine-tuned + high-precision rules",
    "h_cascade": "(h) cascade",
    "h2_cascade_band_only": "(h′) cascade, band only (extra: signals don't escalate)",
    "d_old_all_stages": "(d) old all stages (reference)",
}
NO_JUDGE = ["e_finetuned_only", "g_finetuned_blocking_rules"]


class QuotaExhausted(BaseException):
    """BaseException so the detectors' `except Exception` fallback can't swallow it."""


class JudgeFailed(BaseException):
    pass


# ─────────────────────────────────────────────
# Judge instrumentation: record latency of every call, never fail silently
# ─────────────────────────────────────────────
_calls = []
_real_judge_request = judge_cache.judge_request


def _recording_judge_request(*args, **kwargs):
    try:
        data = _real_judge_request(*args, **kwargs)
    except judge_cache.DailyLimitReached as e:
        raise QuotaExhausted(str(e))
    except Exception as e:
        # Anything else (e.g. a timeout that outlasted the retries) must stop the
        # run: the detector's fallback would otherwise count it as "allow".
        raise JudgeFailed(f"{type(e).__name__}: {e}")
    if "choices" not in data:
        raise JudgeFailed(f"status {data.get('_status')}: {str(data.get('error', data))[:200]}")
    _calls.append({"latency_ms": data.get("_latency_ms", 0.0), "cached": data.get("_cached", False)})
    return data


judge_cache.judge_request = _recording_judge_request


def judge_user_content(prompt):
    # Must match jailbreak_detector.llm_judge exactly
    return f"Classify this prompt:\n\n{prompt[:2000]}"


def has_cached_verdict(prompt):
    cache = judge_cache._jsonl_caches.setdefault(
        os.environ["JUDGE_CACHE_JSONL"], judge_cache.JsonlVerdictCache(os.environ["JUDGE_CACHE_JSONL"]))
    return cache.get(jailbreak_detector.LLM_JUDGE_SYSTEM_PROMPT, judge_user_content(prompt)) is not None


# ─────────────────────────────────────────────
# Data and per-prompt features (no judge)
# ─────────────────────────────────────────────

def load_sets():
    val = load_jsonl(os.path.join(DATA, "val.jsonl"))
    test = load_jsonl(os.path.join(DATA, "test.jsonl"))
    bench = load_jsonl(os.path.join(DATA, "benchmark_200.jsonl"))
    langs = list(csv.DictReader(open(os.path.join(DATA, "benchmark_200_lang.csv"), encoding="utf-8")))
    for r, t in zip(bench, langs):
        r["language"] = t["language"]
    test_300 = random.Random(SEED).sample(test, 300)  # same sample as compare_classifiers.py
    return {"val": val, "test_300": test_300, "deepset_200": bench, "test_full": test}


def features(rows, clf, label):
    """Classifier score, rules fired, and their timings for each prompt."""
    none_pipe = build_pipeline("none")
    out = []
    for i, r in enumerate(rows):
        t0 = time.perf_counter()
        fired = rule_hits(r["text"])
        t1 = time.perf_counter()
        s = clf.predict_proba([r["text"]])[0]
        t2 = time.perf_counter()
        old = none_pipe.analyze(r["text"])
        t3 = time.perf_counter()
        out.append({**r, "s": s, "fired": fired, "rules_ms": (t1 - t0) * 1000,
                    "clf_ms": (t2 - t1) * 1000, "old_rules_ms": (t3 - t2) * 1000,
                    "old_rules_blocked": not old.allowed})
        if (i + 1) % 200 == 0:
            print(f"  features {label}: {i+1}/{len(rows)}", flush=True)
    return out


# ─────────────────────────────────────────────
# 1. SELECT on validation
# ─────────────────────────────────────────────

def select_rules(val):
    stats = {name: {"hits": 0, "tp": 0} for name in all_rule_names()}
    for r in val:
        for name in r["fired"]:
            stats[name]["hits"] += 1
            stats[name]["tp"] += r["label"]
    split = split_rules(stats, MIN_PRECISION, MIN_HITS)
    with open(os.path.join(OUT, "rule_stats.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rule", "val_hits", "val_true_attacks", "val_precision", "decision", "reason"])
        for name in sorted(split, key=lambda n: (split[n]["decision"], -split[n]["hits"])):
            s = split[name]
            w.writerow([name, s["hits"], s["tp"], "" if s["precision"] is None else s["precision"],
                        s["decision"], s["reason"]])
    return split


def select_band(val, signal_rules):
    s = np.array([r["s"] for r in val])
    y = np.array([r["label"] for r in val])
    sig = np.array([any(n in signal_rules for n in r["fired"]) for r in val])
    grid = [round(x, 2) for x in np.arange(0.0, 1.0001, 0.01)]
    rows = []
    for low in grid:
        for high in grid:
            if high <= low:
                continue
            band = (s > low) & (s < high)
            outside = ~band
            pred = (s >= high).astype(int)
            n_out = int(outside.sum())
            acc_out = float((pred[outside] == y[outside]).mean()) if n_out else 1.0
            rows.append({
                "low": low, "high": high, "band_width": round(high - low, 2),
                "band_coverage": round(float(band.mean()), 4),
                "escalated_incl_signals": round(float((band | sig).mean()), 4),
                "accuracy_outside_band": round(acc_out, 4),
                "errors_outside_band": int((pred[outside] != y[outside]).sum()),
            })
    with open(os.path.join(OUT, "band_sweep.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    ok = [r for r in rows if r["band_coverage"] <= BAND_MAX_COVERAGE
          and r["accuracy_outside_band"] >= BAND_MIN_OUTSIDE_ACC]
    if not ok:
        raise SystemExit("No band meets the accuracy/coverage targets on validation")
    # Cheapest band that meets the target; ties → higher accuracy, then narrower band
    best = min(ok, key=lambda r: (r["band_coverage"], -r["accuracy_outside_band"], r["band_width"]))
    # Frontier for the summary: best accuracy reachable at each coverage budget
    frontier = []
    for budget in [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40]:
        cand = [r for r in rows if r["band_coverage"] <= budget]
        if cand:
            top = max(cand, key=lambda r: (r["accuracy_outside_band"], -r["band_coverage"]))
            frontier.append({"coverage_budget": budget, **top})
    return best, frontier


# ─────────────────────────────────────────────
# 2. JUDGE
# ─────────────────────────────────────────────

def judge_one(prompt):
    _calls.clear()
    is_attack, conf, reason = jailbreak_detector.llm_judge(prompt)
    failed = reason.startswith(JUDGE_FAILURE_PREFIXES)
    return {"attack": bool(is_attack), "confidence": conf, "unparseable": failed,
            "latency_ms": sum(c["latency_ms"] for c in _calls), "n_calls": len(_calls)}


def run_judge(sets_needing_judge):
    prompts = [r for rows in sets_needing_judge for r in rows]
    try:
        for i, r in enumerate(prompts):
            r["judge"] = judge_one(r["text"])
            if (i + 1) % 50 == 0:
                print(f"  judge: {i+1}/{len(prompts)}", flush=True)
        old_pipe = build_pipeline("llama")
        for i, r in enumerate(prompts):
            _calls.clear()
            res = old_pipe.analyze(r["text"])
            r["old_llm_blocked"] = not res.allowed
            r["old_judge_ms"] = sum(c["latency_ms"] for c in _calls)
            r["old_judge_calls"] = len(_calls)
            if (i + 1) % 100 == 0:
                print(f"  old pipeline (d): {i+1}/{len(prompts)}", flush=True)
    except QuotaExhausted as e:
        left = sum(1 for r in prompts if not has_cached_verdict(r["text"]))
        raise SystemExit(f"\nGroq daily quota reached: {e}\n"
                         f"Saved verdicts are in {os.environ['JUDGE_CACHE_JSONL']}.\n"
                         f"{left} of {len(prompts)} prompts still need a judge verdict "
                         f"(plus any old-pipeline injection-template calls). Re-run later to resume.")


# ─────────────────────────────────────────────
# 3. EVALUATE
# ─────────────────────────────────────────────

def predictions(r, cfg, has_judge):
    s, fired = r["s"], r["fired"]
    p = {"e_finetuned_only": int(s >= cfg.threshold),
         "g_finetuned_blocking_rules": int(local_only_decision(s, fired, cfg)[0] == BLOCK)}
    lat = {"e_finetuned_only": r["clf_ms"], "g_finetuned_blocking_rules": r["rules_ms"] + r["clf_ms"]}
    calls = {"e_finetuned_only": 0, "g_finetuned_blocking_rules": 0}
    if has_judge:
        j = r["judge"]
        p["f_judge_only"] = int(j["attack"])
        lat["f_judge_only"] = j["latency_ms"]
        calls["f_judge_only"] = j["n_calls"]
        r["route"] = route(s, fired, cfg)[0]
        # h' is the same cascade with signal rules removed, so they can't escalate
        band_cfg = CascadeConfig(cfg.threshold, cfg.low, cfg.high, cfg.blocking_rules, [], cfg.model_dir)
        for name, c in [("h_cascade", cfg), ("h2_cascade_band_only", band_cfg)]:
            decision = route(s, fired, c)[0]
            if decision == JUDGE:
                p[name] = int(j["attack"])
                lat[name] = r["rules_ms"] + r["clf_ms"] + j["latency_ms"]
                calls[name] = j["n_calls"]
            else:
                p[name] = int(decision == BLOCK)
                lat[name] = r["rules_ms"] + r["clf_ms"]
                calls[name] = 0
        p["d_old_all_stages"] = int(r["old_llm_blocked"] or s >= cfg.threshold)
        lat["d_old_all_stages"] = r["old_rules_ms"] + r["old_judge_ms"] + r["clf_ms"]
        calls["d_old_all_stages"] = r["old_judge_calls"]
    r["pred"], r["latency_ms"], r["judge_calls"] = p, lat, calls


def bootstrap(y, p, n=1000, seed=SEED):
    rng = np.random.default_rng(seed)
    y, p = np.asarray(y), np.asarray(p)
    idx = rng.integers(0, len(y), size=(n, len(y)))
    yy, pp = y[idx], p[idx]
    tp = ((yy == 1) & (pp == 1)).sum(1)
    fp = ((yy == 0) & (pp == 1)).sum(1)
    fn = ((yy == 1) & (pp == 0)).sum(1)
    tn = ((yy == 0) & (pp == 0)).sum(1)
    with np.errstate(divide="ignore", invalid="ignore"):
        recall = np.where(tp + fn > 0, tp / (tp + fn), 0.0)
        prec = np.where(tp + fp > 0, tp / (tp + fp), 0.0)
        f1 = np.where(prec + recall > 0, 2 * prec * recall / (prec + recall), 0.0)
        fpr = np.where(fp + tn > 0, fp / (fp + tn), 0.0)
    ci = lambda a: (round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4))
    return {"recall_ci": ci(recall), "f1_ci": ci(f1), "fpr_ci": ci(fpr)}


def summarize(rows, configs):
    y = [r["label"] for r in rows]
    out = {}
    for c in configs:
        p = [r["pred"][c] for r in rows]
        m = scores(y, p)
        m.update(bootstrap(y, p))
        lat = sorted(r["latency_ms"][c] for r in rows)
        calls = [r["judge_calls"][c] for r in rows]
        m["latency_ms_mean"] = round(float(np.mean(lat)), 1)
        m["latency_ms_p95"] = round(float(lat[int(len(lat) * 0.95)]), 1)
        m["pct_sent_to_judge"] = round(100 * float(np.mean([k > 0 for k in calls])), 1)
        m["judge_calls_per_1000"] = round(1000 * float(np.mean(calls)), 0)
        out[c] = m
    return out


def fmt_ci(m, k, pct=True):
    lo, hi = m[f"{k}_ci"]
    v = m[k]
    return f"{v:.1%} [{lo:.1%}–{hi:.1%}]" if pct else f"{v:.3f} [{lo:.3f}–{hi:.3f}]"


def write_outputs(results, lang_results, split, band, frontier, cfg, sets, judge_stats, best):
    with open(os.path.join(OUT, "comparison.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["set", "config", "n", "tp", "fp", "tn", "fn", "recall", "recall_ci_low", "recall_ci_high",
                    "precision", "f1", "f1_ci_low", "f1_ci_high", "fpr", "fpr_ci_low", "fpr_ci_high",
                    "latency_ms_mean", "latency_ms_p95", "pct_sent_to_judge", "judge_calls_per_1000"])
        for set_name, res in results.items():
            for c, m in res.items():
                w.writerow([set_name, c, m["n"], m["tp"], m["fp"], m["tn"], m["fn"], m["recall"], *m["recall_ci"],
                            m["precision"], m["f1"], *m["f1_ci"], m["fpr"], *m["fpr_ci"],
                            m["latency_ms_mean"], m["latency_ms_p95"], m["pct_sent_to_judge"],
                            m["judge_calls_per_1000"]])
    with open(os.path.join(OUT, "language_breakdown.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["language", "config", "n", "attacks", "tp", "fp", "fn", "recall", "precision", "f1", "fpr"])
        for (lang, c), m in lang_results.items():
            w.writerow([lang, c, m["n"], m["tp"] + m["fn"], m["tp"], m["fp"], m["fn"],
                        m["recall"], m["precision"], m["f1"], m["fpr"]])

    L = ["# Cascade evaluation", "",
         f"Judge: `{judge_cache.JUDGE_MODEL}`, temperature {judge_cache.judge_temperature()}, "
         "jailbreak-detector template. Every threshold, rule decision and band below was chosen on the "
         "**validation** set; test and deepset were only scored. CIs are 95% bootstrap intervals "
         "(1,000 resamples, seed 42).", "",
         f"Fine-tuned model: `{cfg.model_dir}`, threshold {cfg.threshold} (validation).", "",
         "## Experiment 1: rule split (validation, n=912)", "",
         f"Blocking = validation precision ≥ {MIN_PRECISION:.0%} with ≥ {MIN_HITS} hits. Everything else is a signal.",
         "", "| Rule | Hits | Attacks | Precision | Decision | Why |", "|---|---|---|---|---|---|"]
    for name in sorted(split, key=lambda n: (split[n]["decision"], -split[n]["hits"])):
        s = split[name]
        prec = "–" if s["precision"] is None else f"{s['precision']:.1%}"
        L.append(f"| `{name}` | {s['hits']} | {s['tp']} | {prec} | **{s['decision']}** | {s['reason']} |")

    L += ["", "## Experiment 3: cascade band (validation, no judge calls)", "",
          f"Chosen: **LOW = {band['low']}, HIGH = {band['high']}**. The band covers {band['band_coverage']:.1%} of "
          f"validation prompts ({band['escalated_incl_signals']:.1%} including signal-rule escalations); outside it "
          f"the classifier is {band['accuracy_outside_band']:.1%} accurate "
          f"(target ≥ {BAND_MIN_OUTSIDE_ACC:.0%} with coverage ≤ {BAND_MAX_COVERAGE:.0%}; cheapest qualifying band).",
          "", "Best accuracy outside the band at each coverage budget (full grid in `band_sweep.csv`):", "",
          "| Coverage budget | LOW | HIGH | Band width | Band coverage | Escalated incl. signals | Accuracy outside band |",
          "|---|---|---|---|---|---|---|"]
    for r in frontier:
        L.append(f"| ≤ {r['coverage_budget']:.0%} | {r['low']} | {r['high']} | {r['band_width']} | "
                 f"{r['band_coverage']:.1%} | {r['escalated_incl_signals']:.1%} | {r['accuracy_outside_band']:.1%} |")

    for set_name, res in results.items():
        n = next(iter(res.values()))["n"]
        L += ["", f"## {set_name} (n={n})", "",
              "| Config | Recall | Precision | F1 | FPR | Mean ms | p95 ms | % to judge | Judge calls / 1k |",
              "|---|---|---|---|---|---|---|---|---|"]
        for c, m in res.items():
            L.append(f"| {CONFIGS[c]} | {fmt_ci(m, 'recall')} | {m['precision']:.1%} | {fmt_ci(m, 'f1', False)} | "
                     f"{fmt_ci(m, 'fpr')} | {m['latency_ms_mean']:.0f} | {m['latency_ms_p95']:.0f} | "
                     f"{m['pct_sent_to_judge']:.0f}% | {m['judge_calls_per_1000']:.0f} |")

    L += ["", "## deepset_200 by language", "",
          "| Config | Language | n | Attacks | Recall | Precision | F1 | FPR |", "|---|---|---|---|---|---|---|---|"]
    for (lang, c), m in lang_results.items():
        L.append(f"| {CONFIGS[c]} | {lang} | {m['n']} | {m['tp'] + m['fn']} | {m['recall']:.1%} | "
                 f"{m['precision']:.1%} | {m['f1']:.3f} | {m['fpr']:.1%} |")

    L += ["", "## Judge usage", "",
          f"- Verdicts: {judge_stats['verdicts']} prompts, {judge_stats['unparseable']} unparseable "
          "(counted as 'allow', as the gateway would). Network errors are retried and otherwise "
          "stop the run, so none are counted as verdicts.",
          f"- Mean judge latency per verdict: {judge_stats['mean_latency_ms']:.0f} ms "
          "(recorded on the original, uncached call).", "",
          f"Best config for error analysis (highest mean F1 over test_300 and deepset_200): **{CONFIGS[best]}**. "
          "Errors are in `errors_best.csv`."]
    with open(os.path.join(OUT, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return "\n".join(L)


def write_errors(sets, best, cfg):
    rng = random.Random(SEED)
    rows = [("test_300", r) for r in sets["test_300"]] + [("deepset_200", r) for r in sets["deepset_200"]]
    fps = [(s, r) for s, r in rows if r["label"] == 0 and r["pred"][best] == 1]
    fns = [(s, r) for s, r in rows if r["label"] == 1 and r["pred"][best] == 0]
    picked = [("false_positive", x) for x in (fps if len(fps) <= 30 else rng.sample(fps, 30))]
    picked += [("false_negative", x) for x in (fns if len(fns) <= 30 else rng.sample(fns, 30))]
    with open(os.path.join(OUT, "errors_best.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["error_type", "set", "source", "language", "label", "classifier_score", "judge_attack",
                    "route", "rules_fired", "auto_flag_label_disagrees_with_model_and_judge", "text"])
        for kind, (set_name, r) in picked:
            disagree = (r["judge"]["attack"] != bool(r["label"])) and (
                (r["label"] == 0 and r["s"] >= 0.9) or (r["label"] == 1 and r["s"] <= 0.1))
            w.writerow([kind, set_name, r.get("source"), r.get("language") or "", r["label"], round(r["s"], 3),
                        int(r["judge"]["attack"]), r.get("route", ""), ";".join(r["fired"]), int(disagree),
                        " ".join(r["text"].split())])
    return len(fps), len(fns)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=os.path.join(ROOT, "models", "distilbert"))
    ap.add_argument("--no-judge", action="store_true", help="stop after selection (no API calls)")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    random.seed(SEED)
    np.random.seed(SEED)

    clf = FineTunedClassifier(args.model_dir)
    clf.predict_proba(["warm-up"])
    sets = load_sets()
    print("Scoring classifier + rules (no judge)...")
    for name in ["val", "test_300", "deepset_200", "test_full"]:
        sets[name] = features(sets[name], clf, name)

    # 1. SELECT — validation only
    split = select_rules(sets["val"])
    blocking = sorted(n for n, s in split.items() if s["decision"] == "blocking")
    signal = sorted(n for n, s in split.items() if s["decision"] == "signal")
    band, frontier = select_band(sets["val"], set(signal))
    cfg = CascadeConfig(threshold=clf.threshold, low=band["low"], high=band["high"],
                        blocking_rules=blocking, signal_rules=signal,
                        model_dir=os.path.relpath(args.model_dir, ROOT).replace("\\", "/"))
    with open(CONFIG_PATH, "w") as f:
        json.dump({"chosen_on": "validation", "model_dir": cfg.model_dir, "threshold": cfg.threshold,
                   "low": cfg.low, "high": cfg.high, "blocking_rules": blocking, "signal_rules": signal,
                   "rule_criteria": {"min_precision": MIN_PRECISION, "min_hits": MIN_HITS},
                   "band_criteria": {"min_accuracy_outside": BAND_MIN_OUTSIDE_ACC,
                                     "max_coverage": BAND_MAX_COVERAGE},
                   "validation_band": band}, f, indent=2)
    print(f"Blocking rules: {blocking}\nBand: LOW={cfg.low} HIGH={cfg.high} "
          f"(coverage {band['band_coverage']:.1%}, accuracy outside {band['accuracy_outside_band']:.1%})")
    if args.no_judge:
        print(f"Selection written to {CONFIG_PATH} and {OUT}. Stopping before judge calls.")
        return

    # 2. JUDGE
    if not os.environ.get("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY not set (put it in .env) or pass --no-judge")
    print("Judge phase (cached verdicts are reused)...")
    run_judge([sets["test_300"], sets["deepset_200"]])

    # 3. EVALUATE
    for name in ["test_300", "deepset_200"]:
        for r in sets[name]:
            predictions(r, cfg, has_judge=True)
    for r in sets["test_full"]:
        predictions(r, cfg, has_judge=False)
    results = {
        "test_300": summarize(sets["test_300"], list(CONFIGS)),
        "deepset_200": summarize(sets["deepset_200"], list(CONFIGS)),
        "test_full": summarize(sets["test_full"], NO_JUDGE),
    }
    lang_results = {}
    for c in CONFIGS:
        for lang in ["en", "de", "other"]:
            sub = [r for r in sets["deepset_200"] if r["language"] == lang]
            lang_results[(lang, c)] = scores([r["label"] for r in sub], [r["pred"][c] for r in sub])
    judged = [r for n in ["test_300", "deepset_200"] for r in sets[n]]
    judge_stats = {"verdicts": len(judged), "unparseable": sum(r["judge"]["unparseable"] for r in judged),
                   "mean_latency_ms": float(np.mean([r["judge"]["latency_ms"] for r in judged]))}
    best = max(CONFIGS, key=lambda c: (results["test_300"][c]["f1"] + results["deepset_200"][c]["f1"]) / 2)
    n_fp, n_fn = write_errors(sets, best, cfg)

    with open(os.path.join(OUT, "rows.jsonl"), "w", encoding="utf-8") as f:
        for name in ["test_300", "deepset_200", "test_full"]:
            for r in sets[name]:
                f.write(json.dumps({"set": name, "text": r["text"], "label": r["label"],
                                    "source": r.get("source"), "language": r.get("language"),
                                    "s": round(r["s"], 4), "fired": r["fired"], "route": r.get("route"),
                                    "judge_attack": r.get("judge", {}).get("attack"),
                                    "pred": r["pred"], "latency_ms": {k: round(v, 1) for k, v in r["latency_ms"].items()},
                                    "judge_calls": r["judge_calls"]}, ensure_ascii=False) + "\n")
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump({"config": cfg.__dict__, "results": results, "best": best, "judge": judge_stats,
                   "n_errors_best": {"false_positives": n_fp, "false_negatives": n_fn}}, f, indent=2)
    print(write_outputs(results, lang_results, split, band, frontier, cfg, sets, judge_stats, best))


if __name__ == "__main__":
    main()
