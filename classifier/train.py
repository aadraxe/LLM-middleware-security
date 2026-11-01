"""
train.py
Fine-tune a small encoder for binary attack/benign classification.

Plain PyTorch loop (no Trainer) so it runs the same on CPU and on a Colab GPU.
Every run appends one line of metrics to results/experiments.jsonl and saves
per-prompt probabilities to results/runs/<run_name>/preds.json.

The decision threshold is chosen on the VALIDATION set, then frozen before
the test set and the 200-prompt benchmark are scored.

Usage:
    python classifier/train.py --model distilbert-base-uncased --run-name distilbert
    python classifier/train.py --model microsoft/deberta-v3-small --run-name deberta-small
    python classifier/train.py --model microsoft/deberta-v3-base --lora --run-name deberta-base-lora
"""

import argparse
import json
import os
import platform
import random
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import torch
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from classifier.metrics import scores, choose_threshold, load_jsonl

DATA = os.path.join(ROOT, "data", "processed")
RESULTS = os.path.join(ROOT, "results")


def set_seed(seed):
    random.seed(seed)
    torch.manual_seed(seed)


def length_bucketed_batches(rows, batch_size, rng):
    """Group similar-length prompts into batches: big CPU speed-up from less padding."""
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    chunk = batch_size * 50
    batches = []
    for i in range(0, len(idx), chunk):
        part = sorted(idx[i:i + chunk], key=lambda j: len(rows[j]["text"]))
        batches += [part[k:k + batch_size] for k in range(0, len(part), batch_size)]
    rng.shuffle(batches)
    return batches


@torch.no_grad()
def predict(model, tokenizer, texts, max_len, device, batch_size=32):
    model.eval()
    order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
    probs = [0.0] * len(texts)
    for i in range(0, len(order), batch_size):
        ids = order[i:i + batch_size]
        enc = tokenizer([texts[j] for j in ids], truncation=True, max_length=max_len,
                        padding=True, return_tensors="pt").to(device)
        p = torch.softmax(model(**enc).logits.float(), dim=-1)[:, 1].tolist()
        for j, pj in zip(ids, p):
            probs[j] = pj
    return probs


def build_model(args):
    # Force fp32: transformers v5 loads in the checkpoint's dtype, and
    # deberta-v3 checkpoints are fp16, which diverges to NaN under AdamW.
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=2, dtype=torch.float32)
    if not args.lora:
        return model
    from peft import LoraConfig, get_peft_model, TaskType
    cfg = LoraConfig(
        task_type=TaskType.SEQ_CLS, r=args.lora_r, lora_alpha=args.lora_r * 2,
        lora_dropout=0.1, target_modules=args.lora_targets.split(","),
        modules_to_save=["classifier", "pooler"],
    )
    model = get_peft_model(model, cfg)
    model.print_trainable_parameters()
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="distilbert-base-uncased")
    ap.add_argument("--run-name", required=True)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=None, help="default 3e-5 full FT, 3e-4 LoRA")
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--warmup", type=float, default=0.06)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit-train", type=int, default=0, help="subsample train (smoke tests)")
    ap.add_argument("--lora", action="store_true")
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-targets", default="query_proj,key_proj,value_proj")
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "models"))
    ap.add_argument("--results-dir", default=RESULTS)
    args = ap.parse_args()
    lr = args.lr or (3e-4 if args.lora else 3e-5)

    set_seed(args.seed)
    rng = random.Random(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cpu":
        torch.set_num_threads(os.cpu_count() or 4)
    print(f"device={device} threads={torch.get_num_threads()}")

    train = load_jsonl(os.path.join(DATA, "train.jsonl"))
    val = load_jsonl(os.path.join(DATA, "val.jsonl"))
    test = load_jsonl(os.path.join(DATA, "test.jsonl"))
    bench = load_jsonl(os.path.join(DATA, "benchmark_200.jsonl"))
    if args.limit_train:
        train = rng.sample(train, args.limit_train)

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = build_model(args).to(device)
    n_trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    n_total = sum(p.numel() for p in model.parameters())

    optim = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad],
                              lr=lr, weight_decay=0.01)
    steps_per_epoch = -(-len(train) // args.batch_size)
    total_steps = steps_per_epoch * args.epochs
    warm = max(1, int(total_steps * args.warmup))
    sched = torch.optim.lr_scheduler.LambdaLR(
        optim, lambda s: min((s + 1) / warm, max(0.0, (total_steps - s) / (total_steps - warm))))

    best = {"f1": -1}
    t0 = time.time()
    step = 0
    for epoch in range(args.epochs):
        model.train()
        for batch_idx in length_bucketed_batches(train, args.batch_size, rng):
            rows = [train[i] for i in batch_idx]
            enc = tokenizer([r["text"] for r in rows], truncation=True, max_length=args.max_len,
                            padding=True, return_tensors="pt").to(device)
            labels = torch.tensor([r["label"] for r in rows], device=device)
            loss = model(**enc, labels=labels).loss
            if not torch.isfinite(loss):
                raise SystemExit(f"non-finite loss at step {step}: training diverged, nothing saved")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optim.step()
            sched.step()
            optim.zero_grad()
            step += 1
            if step % 25 == 0:
                el = time.time() - t0
                print(f"epoch {epoch+1} step {step}/{total_steps} loss {loss.item():.4f} "
                      f"elapsed {el/60:.1f}m eta {el/step*(total_steps-step)/60:.1f}m", flush=True)

        val_probs = predict(model, tokenizer, [r["text"] for r in val], args.max_len, device)
        t = choose_threshold([r["label"] for r in val], val_probs)
        m = scores([r["label"] for r in val], [int(p >= t) for p in val_probs])
        print(f"epoch {epoch+1} val f1={m['f1']} (threshold {t})", flush=True)
        if m["f1"] > best["f1"]:
            trainable = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            best = {"f1": m["f1"], "epoch": epoch + 1, "state": trainable}
    train_minutes = (time.time() - t0) / 60

    model.load_state_dict(best["state"])
    if args.lora:
        model = model.merge_and_unload()

    # Threshold chosen on validation only, then frozen.
    val_probs = predict(model, tokenizer, [r["text"] for r in val], args.max_len, device)
    threshold = choose_threshold([r["label"] for r in val], val_probs)
    test_probs = predict(model, tokenizer, [r["text"] for r in test], args.max_len, device)
    bench_probs = predict(model, tokenizer, [r["text"] for r in bench], args.max_len, device)

    def at(rows, probs, thr):
        return scores([r["label"] for r in rows], [int(p >= thr) for p in probs])

    # Single-prompt CPU latency, the way the gateway calls it
    model.to("cpu")
    model.eval()
    lat = []
    with torch.no_grad():
        for r in bench:
            s = time.perf_counter()
            enc = tokenizer([r["text"]], truncation=True, max_length=args.max_len, return_tensors="pt")
            model(**enc)
            lat.append((time.perf_counter() - s) * 1000)

    save_dir = os.path.join(args.out_dir, args.run_name)
    model.save_pretrained(save_dir)
    tokenizer.save_pretrained(save_dir)
    with open(os.path.join(save_dir, "threshold.json"), "w") as f:
        json.dump({"threshold": threshold, "chosen_on": "validation", "max_length": args.max_len}, f)

    record = {
        "run_name": args.run_name,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": args.model, "lora": args.lora,
        "lora_r": args.lora_r if args.lora else None,
        "epochs": args.epochs, "best_epoch": best["epoch"], "batch_size": args.batch_size,
        "lr": lr, "max_len": args.max_len, "seed": args.seed,
        "n_train": len(train), "params_total": n_total, "params_trainable": n_trainable,
        "device": device, "cpu": platform.processor(), "train_minutes": round(train_minutes, 1),
        "threshold": threshold,
        "val": at(val, val_probs, threshold),
        "test": at(test, test_probs, threshold),
        "benchmark_200": at(bench, bench_probs, threshold),
        "benchmark_200_at_0.5": at(bench, bench_probs, 0.5),
        "cpu_latency_ms_mean": round(sum(lat) / len(lat), 1),
        "cpu_latency_ms_p95": round(sorted(lat)[int(len(lat) * 0.95)], 1),
    }
    os.makedirs(os.path.join(args.results_dir, "runs", args.run_name), exist_ok=True)
    with open(os.path.join(args.results_dir, "experiments.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")
    with open(os.path.join(args.results_dir, "runs", args.run_name, "preds.json"), "w") as f:
        json.dump({"val": val_probs, "test": test_probs, "benchmark_200": bench_probs}, f)
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
