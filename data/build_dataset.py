"""
build_dataset.py
Build the train / validation / test splits for the fine-tuned classifier,
plus the held-out 200-prompt benchmark.

Label definition:
    1 = attack  (jailbreak or prompt injection attempt)
    0 = benign  (ordinary request, including role-play / persona prompts
                 that do NOT try to override instructions or bypass safety)

Sources (all public on Hugging Face, licenses recorded in data/DATASET.md):
    jackhhao/jailbreak-classification        Apache-2.0   jailbreak + benign
    Lakera/gandalf_ignore_instructions       MIT          injection
    TrustAIRLab/in-the-wild-jailbreak-prompts MIT         jailbreak + regular
    reshabhs/SPML_Chatbot_Prompt_Injection   MIT          injection + benign
    alespalla/chatbot_instruction_prompts    Apache-2.0   benign

The existing benchmark (deepset/prompt-injections, 200-prompt seeded subset)
goes ONLY into data/processed/benchmark_200.jsonl. Every deepset prompt
(all 662, not just the 200) is excluded from train/val/test so the
benchmark stays a clean out-of-distribution check.

Usage:
    python data/build_dataset.py
"""

import os
import sys
import re
import json
import random
import hashlib
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datasets import load_dataset

SEED = 42
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "processed")

# Per-source caps keep any single source from dominating its class.
CAPS = {
    ("spml", 1): 2500,
    ("spml", 0): 1500,
    ("trustair", 0): 1800,
    ("alespalla", 0): None,  # filled to balance the classes
}
MIN_CHARS = 8
MAX_CHARS = 20000


def norm(text: str) -> str:
    """Normalisation used for de-duplication and leakage checks."""
    t = text.lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^\w ]", "", t)
    return t.strip()


def near_key(text: str) -> str:
    """Prefix key: in-the-wild jailbreaks are often the same template with a
    different tail, so the first 200 normalised chars catch near-duplicates."""
    return hashlib.md5(norm(text)[:200].encode()).hexdigest()


# ─────────────────────────────────────────────
# SOURCE LOADERS — each returns [(text, label, source)]
# ─────────────────────────────────────────────

def load_jackhhao():
    ds = load_dataset("jackhhao/jailbreak-classification")
    rows = []
    for split in ds:
        for r in ds[split]:
            rows.append((r["prompt"], 1 if r["type"] == "jailbreak" else 0, "jackhhao"))
    return rows


def load_gandalf():
    ds = load_dataset("Lakera/gandalf_ignore_instructions")
    return [(r["text"], 1, "gandalf") for split in ds for r in ds[split]]


def load_trustair():
    rows = []
    for config, label in [("jailbreak_2023_05_07", 1), ("jailbreak_2023_12_25", 1),
                          ("regular_2023_05_07", 0), ("regular_2023_12_25", 0)]:
        ds = load_dataset("TrustAIRLab/in-the-wild-jailbreak-prompts", config, split="train")
        rows.extend((r["prompt"], label, "trustair") for r in ds)
    return rows


def load_spml():
    ds = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection", split="train")
    return [(r["User Prompt"], int(r["Prompt injection"]), "spml") for r in ds]


def load_alespalla():
    ds = load_dataset("alespalla/chatbot_instruction_prompts", split="train")
    # Strip the trailing " 1" list-number artefacts some prompts carry
    return [(re.sub(r"\s+\d+\s*$", "", r["prompt"]).strip(), 0, "alespalla") for r in ds]


def load_benchmark_200():
    """Exactly the prompts `run_benchmark.py --subset 200` evaluates."""
    from benchmark.run_benchmark import load_data
    return load_data(use_sample=False, subset=200), load_data(use_sample=False, subset=0)


# ─────────────────────────────────────────────
# BUILD
# ─────────────────────────────────────────────

def clean(rows, blocked_keys, seen_exact, seen_near, stats):
    out = []
    for text, label, source in rows:
        if not isinstance(text, str):
            stats["dropped_non_text"] += 1
            continue
        text = text.strip()
        if not (MIN_CHARS <= len(text) <= MAX_CHARS):
            stats["dropped_length"] += 1
            continue
        n = norm(text)
        if n in blocked_keys:
            stats["dropped_benchmark_overlap"] += 1
            continue
        if n in seen_exact:
            # Same text with a different label → ambiguous; mark for removal
            if seen_exact[n] != label:
                stats["conflicting_labels"] += 1
                seen_exact[n] = -1
            stats["dropped_exact_dup"] += 1
            continue
        k = near_key(text)
        if k in seen_near:
            stats["dropped_near_dup"] += 1
            continue
        seen_exact[n] = label
        seen_near.add(k)
        out.append({"text": text, "label": label, "source": source})
    return out


def stratified_split(rows, rng, val_frac=0.1, test_frac=0.1):
    buckets = defaultdict(list)
    for r in rows:
        buckets[(r["source"], r["label"])].append(r)
    train, val, test = [], [], []
    for key in sorted(buckets):
        b = buckets[key]
        rng.shuffle(b)
        n_val, n_test = round(len(b) * val_frac), round(len(b) * test_frac)
        val += b[:n_val]
        test += b[n_val:n_val + n_test]
        train += b[n_val + n_test:]
    for s in (train, val, test):
        rng.shuffle(s)
    return train, val, test


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main():
    rng = random.Random(SEED)
    os.makedirs(OUT_DIR, exist_ok=True)
    stats = Counter()

    bench, deepset_all = load_benchmark_200()
    blocked_keys = {norm(t) for t, _ in deepset_all}
    write_jsonl(os.path.join(OUT_DIR, "benchmark_200.jsonl"),
                [{"text": t, "label": l, "source": "deepset"} for t, l in bench])

    raw = load_jackhhao() + load_gandalf() + load_trustair() + load_spml() + load_alespalla()
    stats["raw_rows"] = len(raw)
    raw_counts = Counter((s, l) for _, l, s in raw)

    # Shuffle before de-dup so which duplicate survives doesn't depend on file order
    rng.shuffle(raw)
    seen_exact, seen_near = {}, set()
    rows = clean(raw, blocked_keys, seen_exact, seen_near, stats)
    # Drop every text that appeared with both labels
    rows = [r for r in rows if seen_exact[norm(r["text"])] != -1]

    # Apply per-source caps
    by_key = defaultdict(list)
    for r in rows:
        by_key[(r["source"], r["label"])].append(r)
    for key, cap in CAPS.items():
        if cap is not None and len(by_key[key]) > cap:
            by_key[key] = rng.sample(by_key[key], cap)

    # Balance: fill benign with alespalla until benign == attack
    n_attack = sum(len(v) for (s, l), v in by_key.items() if l == 1)
    n_benign_other = sum(len(v) for (s, l), v in by_key.items() if l == 0 and s != "alespalla")
    need = max(n_attack - n_benign_other, 0)
    by_key[("alespalla", 0)] = rng.sample(by_key[("alespalla", 0)], min(need, len(by_key[("alespalla", 0)])))

    final = [r for v in by_key.values() for r in v]
    train, val, test = stratified_split(final, rng)

    for name, split in [("train", train), ("val", val), ("test", test)]:
        write_jsonl(os.path.join(OUT_DIR, f"{name}.jsonl"), split)

    # Leakage self-check
    tr = {norm(r["text"]) for r in train}
    assert not tr & {norm(r["text"]) for r in val + test}, "train overlaps val/test"
    assert not tr & blocked_keys, "train overlaps deepset benchmark"

    summary = {
        "seed": SEED,
        "raw_counts": {f"{s}/{l}": n for (s, l), n in sorted(raw_counts.items())},
        "cleaning": dict(stats),
        "final_counts": {f"{s}/{l}": len(v) for (s, l), v in sorted(by_key.items())},
        "splits": {
            name: {"total": len(s), "attack": sum(r["label"] for r in s),
                   "benign": sum(1 - r["label"] for r in s)}
            for name, s in [("train", train), ("val", val), ("test", test)]
        },
        "benchmark_200": {"total": len(bench), "attack": sum(l for _, l in bench),
                          "benign": sum(1 - l for _, l in bench)},
    }
    # Hashes let anyone confirm a rebuild matches (splits are gitignored)
    summary["sha256"] = {}
    for name in ("train", "val", "test", "benchmark_200"):
        with open(os.path.join(OUT_DIR, f"{name}.jsonl"), "rb") as f:
            summary["sha256"][name] = hashlib.sha256(f.read()).hexdigest()
    with open(os.path.join(OUT_DIR, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
