# Dataset for the fine-tuned prompt-attack classifier

Built by [`data/build_dataset.py`](build_dataset.py) with a fixed seed (`42`).
Training splits are not committed (they are rebuilt from the sources); the
SHA-256 of each split is recorded in [`processed/summary.json`](processed/summary.json)
so a rebuild can be checked byte-for-byte.

```bash
python data/build_dataset.py
```

## Label definitions

| Label | Meaning |
|---|---|
| `1` attack | The prompt tries to **jailbreak** the model (bypass safety training, unlock an "unrestricted" persona, extract harmful content through framing) **or inject instructions** (override the application's task or system prompt, exfiltrate the system prompt or secrets, hijack the output). |
| `0` benign | An ordinary request. This deliberately includes role-play and persona prompts ("act as a travel agent", "you are a vegan chef") that set up a character **without** trying to remove restrictions or override instructions, because these are the main source of false alarms. |

Labels come from each source dataset; they were not re-annotated.

## Sources

| Source | License | Used for | Raw rows | Kept |
|---|---|---|---|---|
| [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | jailbreak + benign | 666 / 640 | 160 / 637 |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | injection | 1,000 / 0 | 977 / 0 |
| [TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts) (all four configs) | MIT | jailbreak + regular prompts | 2,071 / 19,456 | 919 / 1,800 |
| [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) (user prompt only) | MIT | injection + benign | 12,542 / 3,470 | 2,500 / 1,500 |
| [alespalla/chatbot_instruction_prompts](https://huggingface.co/datasets/alespalla/chatbot_instruction_prompts) (train split) | Apache-2.0 | benign | 0 / 258,042 | 0 / 619 |

Counts are attack / benign. Licenses were read from each dataset card on 2026-10-31.

**Considered and excluded:** `xTRam1/safe-guard-prompt-injection` and
`geekyrakshit/prompt-injection-dataset` (no license stated on the card), and
`databricks/databricks-dolly-15k` (CC BY-SA 3.0 share-alike; not needed once
alespalla provided enough benign prompts).

## Held-out benchmark: never trained on

[`processed/benchmark_200.jsonl`](processed/benchmark_200.jsonl) is exactly the
set `benchmark/run_benchmark.py --subset 200` evaluates: a `random.seed(42)`
sample of 200 prompts from **[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)**
(Apache-2.0), **78 attacks / 122 benign**, partly in German.

To keep the benchmark a genuinely out-of-distribution check, **all 662 deepset
prompts** (not just the 200) are excluded from train/val/test. Any source
prompt whose normalised text matches a deepset prompt is dropped (42 rows were
removed this way).

## Cleaning

Applied in this order, after a seeded shuffle so which duplicate survives does
not depend on source order:

| Step | Rows removed |
|---|---|
| Length outside 8–20,000 characters | 385 |
| Non-text value | 1 |
| Exact duplicate (lower-cased, whitespace/punctuation-normalised) | 25,180 |
| Near-duplicate (same first 200 normalised characters; catches templated jailbreaks with different tails) | 2,366 |
| Matches a deepset benchmark prompt | 42 |
| Same text appears with **both** labels (all copies dropped) | 108 texts |

jackhhao's jailbreaks overlap heavily with TrustAIRLab's in-the-wild prompts,
which is why only 160 of 666 survive de-duplication.

## Balancing

Per-source caps keep any one source from dominating its class: SPML attacks
2,500, SPML benign 1,500, TrustAIRLab regular 1,800. Benign prompts from
alespalla are then sampled until benign equals attack (4,556 each).

## Splits

Stratified by (source, label), 80 / 10 / 10:

| Split | Total | Attack | Benign |
|---|---|---|---|
| train | 7,288 | 3,644 | 3,644 |
| val | 912 | 456 | 456 |
| test | 912 | 456 | 456 |
| benchmark_200 (deepset, held out) | 200 | 78 | 122 |

`val` is used for model selection and for choosing the decision threshold.
`test` and `benchmark_200` are only scored after the threshold is frozen.

## Known issues

- **Label noise in SPML.** Its "injection" label means "violates the chatbot's system prompt", so it includes some requests that are only policy-violating (e.g. "a recipe with the highest calorie content possible, ignoring any health risks"). SPML is 55% of the attack class.
- **English only.** No training source is German, but part of the deepset benchmark is.
- **Truncation.** Models see the first 256 tokens; in-the-wild jailbreaks are often much longer, so the payload at the end of a long prompt can be cut off.
- **Source shortcuts.** Sources differ in style (e.g. alespalla is short chat turns, TrustAIRLab is long persona prompts), so a model can partly learn "what source is this" rather than "is this an attack". The deepset benchmark, from a different source, is the check against that.
