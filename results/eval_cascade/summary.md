# Cascade evaluation

Judge: `openai/gpt-oss-120b`, temperature 0.0, jailbreak-detector template. Every threshold, rule decision and band below was chosen on the **validation** set; test and deepset were only scored. CIs are 95% bootstrap intervals (1,000 resamples, seed 42).

Fine-tuned model: `models/distilbert`, threshold 0.61 (validation).

## Experiment 1: rule split (validation, n=912)

Blocking = validation precision ≥ 95% with ≥ 10 hits. Everything else is a signal.

| Rule | Hits | Attacks | Precision | Decision | Why |
|---|---|---|---|---|---|
| `jb_regex:safety_bypass` | 28 | 28 | 100.0% | **blocking** | precision 100.0% on 28 hits |
| `pi_regex:instruction_in_data` | 24 | 24 | 100.0% | **blocking** | precision 100.0% on 24 hits |
| `pi_fuzzy:task_switch` | 10 | 10 | 100.0% | **blocking** | precision 100.0% on 10 hits |
| `pi_fuzzy:exfiltration_intent` | 64 | 50 | 78.1% | **signal** | precision 78.1% < 95% |
| `jb_regex:instruction_override` | 57 | 49 | 86.0% | **signal** | precision 86.0% < 95% |
| `pi_regex:context_boundary_attack` | 56 | 12 | 21.4% | **signal** | precision 21.4% < 95% |
| `jb_fuzzy:leet_encoding_detected` | 49 | 40 | 81.6% | **signal** | precision 81.6% < 95% |
| `jb_fuzzy:fictional_framing_bypass` | 46 | 43 | 93.5% | **signal** | precision 93.5% < 95% |
| `jb_fuzzy:excessive_length` | 20 | 10 | 50.0% | **signal** | precision 50.0% < 95% |
| `jb_regex:role_manipulation` | 18 | 15 | 83.3% | **signal** | precision 83.3% < 95% |
| `jb_fuzzy:gradual_escalation` | 9 | 9 | 100.0% | **signal** | only 9 validation hits (< 10) |
| `pi_regex:output_manipulation` | 9 | 8 | 88.9% | **signal** | only 9 validation hits (< 10) |
| `pi_fuzzy:injection_after_processing_task` | 9 | 6 | 66.7% | **signal** | only 9 validation hits (< 10) |
| `pi_fuzzy:data_destination_url` | 5 | 1 | 20.0% | **signal** | only 5 validation hits (< 10) |
| `jb_regex:token_smuggling` | 4 | 2 | 50.0% | **signal** | only 4 validation hits (< 10) |
| `jb_fuzzy:unicode_manipulation` | 4 | 1 | 25.0% | **signal** | only 4 validation hits (< 10) |
| `pi_fuzzy:fake_conversation_turns` | 4 | 4 | 100.0% | **signal** | only 4 validation hits (< 10) |
| `jb_regex:encoding_obfuscation` | 3 | 0 | 0.0% | **signal** | only 3 validation hits (< 10) |
| `jb_regex:system_prompt_extraction` | 2 | 2 | 100.0% | **signal** | only 2 validation hits (< 10) |
| `jb_fuzzy:multi_persona_injection` | 2 | 2 | 100.0% | **signal** | only 2 validation hits (< 10) |
| `pi_regex:indirect_injection_marker` | 2 | 2 | 100.0% | **signal** | only 2 validation hits (< 10) |
| `jb_fuzzy:social_engineering` | 1 | 1 | 100.0% | **signal** | only 1 validation hits (< 10) |
| `jb_fuzzy:extreme_length_dos` | 1 | 1 | 100.0% | **signal** | only 1 validation hits (< 10) |
| `pi_regex:data_exfiltration` | 1 | 1 | 100.0% | **signal** | only 1 validation hits (< 10) |
| `jb_regex:escalation_primer` | 0 | 0 | – | **signal** | only 0 validation hits (< 10) |
| `jb_fuzzy:base64_encoded_attack` | 0 | 0 | – | **signal** | only 0 validation hits (< 10) |
| `jb_fuzzy:unicode_suspicious` | 0 | 0 | – | **signal** | only 0 validation hits (< 10) |
| `jb_fuzzy:low_entropy_token_stuffing` | 0 | 0 | – | **signal** | only 0 validation hits (< 10) |
| `jb_fuzzy:multi_turn_escalation` | 0 | 0 | – | **signal** | only 0 validation hits (< 10) |

## Experiment 3: cascade band (validation, no judge calls)

Chosen: **LOW = 0.19, HIGH = 0.95**. The band covers 7.1% of validation prompts (29.7% including signal-rule escalations); outside it the classifier is 97.0% accurate (target ≥ 97% with coverage ≤ 25%; cheapest qualifying band).

Best accuracy outside the band at each coverage budget (full grid in `band_sweep.csv`):

| Coverage budget | LOW | HIGH | Band width | Band coverage | Escalated incl. signals | Accuracy outside band |
|---|---|---|---|---|---|---|
| ≤ 0% | 0.59 | 0.6 | 0.01 | 0.0% | 26.0% | 95.1% |
| ≤ 5% | 0.42 | 0.95 | 0.53 | 4.9% | 29.2% | 96.7% |
| ≤ 10% | 0.11 | 0.95 | 0.84 | 8.8% | 30.0% | 97.5% |
| ≤ 15% | 0.07 | 0.99 | 0.92 | 14.6% | 33.0% | 98.1% |
| ≤ 20% | 0.04 | 0.99 | 0.95 | 17.3% | 34.5% | 98.4% |
| ≤ 25% | 0.01 | 0.99 | 0.98 | 24.2% | 39.5% | 99.0% |
| ≤ 30% | 0.01 | 0.99 | 0.98 | 24.2% | 39.5% | 99.0% |
| ≤ 40% | 0.01 | 0.99 | 0.98 | 24.2% | 39.5% | 99.0% |

## test_300 (n=300)

| Config | Recall | Precision | F1 | FPR | Mean ms | p95 ms | % to judge | Judge calls / 1k |
|---|---|---|---|---|---|---|---|---|
| (e) fine-tuned alone | 90.5% [85.7%–94.6%] | 96.0% | 0.932 [0.900–0.959] | 4.2% [1.3%–7.6%] | 47 | 100 | 0% | 0 |
| (f) judge alone | 66.5% [59.3%–73.8%] | 87.5% | 0.755 [0.699–0.811] | 10.6% [6.0%–15.8%] | 1346 | 1572 | 100% | 1000 |
| (g) fine-tuned + high-precision rules | 90.5% [85.7%–94.6%] | 96.0% | 0.932 [0.900–0.959] | 4.2% [1.3%–7.6%] | 51 | 111 | 0% | 0 |
| (h) cascade | 95.6% [91.9%–98.6%] | 91.0% | 0.932 [0.903–0.960] | 10.6% [5.7%–16.2%] | 251 | 1519 | 15% | 147 |
| (h′) cascade, band only (extra: signals don't escalate) | 94.3% [90.4%–97.5%] | 93.7% | 0.940 [0.911–0.966] | 7.0% [3.0%–11.5%] | 146 | 1382 | 7% | 70 |
| (d) old all stages (reference) | 96.8% [93.8%–99.3%] | 83.2% | 0.895 [0.860–0.928] | 21.8% [15.2%–29.0%] | 1430 | 2939 | 91% | 957 |

## deepset_200 (n=200)

| Config | Recall | Precision | F1 | FPR | Mean ms | p95 ms | % to judge | Judge calls / 1k |
|---|---|---|---|---|---|---|---|---|
| (e) fine-tuned alone | 21.8% [12.8%–32.0%] | 94.4% | 0.354 [0.225–0.481] | 0.8% [0.0%–2.6%] | 24 | 54 | 0% | 0 |
| (f) judge alone | 50.0% [39.4%–61.5%] | 100.0% | 0.667 [0.565–0.762] | 0.0% [0.0%–0.0%] | 1660 | 2890 | 100% | 1000 |
| (g) fine-tuned + high-precision rules | 21.8% [12.8%–32.0%] | 94.4% | 0.354 [0.225–0.481] | 0.8% [0.0%–2.6%] | 25 | 56 | 0% | 0 |
| (h) cascade | 29.5% [20.2%–39.7%] | 100.0% | 0.455 [0.337–0.569] | 0.0% [0.0%–0.0%] | 222 | 1556 | 12% | 125 |
| (h′) cascade, band only (extra: signals don't escalate) | 28.2% [18.5%–38.1%] | 100.0% | 0.440 [0.312–0.552] | 0.0% [0.0%–0.0%] | 211 | 1556 | 12% | 115 |
| (d) old all stages (reference) | 52.6% [41.9%–64.2%] | 97.6% | 0.683 [0.582–0.776] | 0.8% [0.0%–2.6%] | 1671 | 2968 | 98% | 990 |

## test_full (n=912)

| Config | Recall | Precision | F1 | FPR | Mean ms | p95 ms | % to judge | Judge calls / 1k |
|---|---|---|---|---|---|---|---|---|
| (e) fine-tuned alone | 92.5% [90.0%–94.7%] | 95.3% | 0.939 [0.923–0.954] | 4.6% [2.8%–6.8%] | 46 | 100 | 0% | 0 |
| (g) fine-tuned + high-precision rules | 92.8% [90.3%–94.9%] | 94.8% | 0.938 [0.921–0.953] | 5.0% [3.2%–7.2%] | 49 | 113 | 0% | 0 |

## deepset_200 by language

| Config | Language | n | Attacks | Recall | Precision | F1 | FPR |
|---|---|---|---|---|---|---|---|
| (e) fine-tuned alone | en | 115 | 47 | 34.0% | 100.0% | 0.508 | 0.0% |
| (e) fine-tuned alone | de | 81 | 27 | 3.7% | 50.0% | 0.069 | 1.8% |
| (e) fine-tuned alone | other | 4 | 4 | 0.0% | 0.0% | 0.000 | 0.0% |
| (f) judge alone | en | 115 | 47 | 55.3% | 100.0% | 0.712 | 0.0% |
| (f) judge alone | de | 81 | 27 | 40.7% | 100.0% | 0.579 | 0.0% |
| (f) judge alone | other | 4 | 4 | 50.0% | 100.0% | 0.667 | 0.0% |
| (g) fine-tuned + high-precision rules | en | 115 | 47 | 34.0% | 100.0% | 0.508 | 0.0% |
| (g) fine-tuned + high-precision rules | de | 81 | 27 | 3.7% | 50.0% | 0.069 | 1.8% |
| (g) fine-tuned + high-precision rules | other | 4 | 4 | 0.0% | 0.0% | 0.000 | 0.0% |
| (h) cascade | en | 115 | 47 | 38.3% | 100.0% | 0.554 | 0.0% |
| (h) cascade | de | 81 | 27 | 18.5% | 100.0% | 0.312 | 0.0% |
| (h) cascade | other | 4 | 4 | 0.0% | 0.0% | 0.000 | 0.0% |
| (h′) cascade, band only (extra: signals don't escalate) | en | 115 | 47 | 36.2% | 100.0% | 0.531 | 0.0% |
| (h′) cascade, band only (extra: signals don't escalate) | de | 81 | 27 | 18.5% | 100.0% | 0.312 | 0.0% |
| (h′) cascade, band only (extra: signals don't escalate) | other | 4 | 4 | 0.0% | 0.0% | 0.000 | 0.0% |
| (d) old all stages (reference) | en | 115 | 47 | 57.5% | 100.0% | 0.730 | 0.0% |
| (d) old all stages (reference) | de | 81 | 27 | 40.7% | 91.7% | 0.564 | 1.8% |
| (d) old all stages (reference) | other | 4 | 4 | 75.0% | 100.0% | 0.857 | 0.0% |

## Judge usage

- Verdicts: 500 prompts, 0 unparseable (counted as 'allow', as the gateway would). Network errors are retried and otherwise stop the run, so none are counted as verdicts.
- Mean judge latency per verdict: 1472 ms (recorded on the original, uncached call).

Best config for error analysis (highest mean F1 over test_300 and deepset_200): **(d) old all stages (reference)**. Errors are in `errors_best.csv`.
