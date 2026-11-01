Fine-tuned model: `models\distilbert` (threshold 0.61, chosen on validation)
LLM judge: `openai/gpt-oss-120b` via Groq

### benchmark_200 (n=200)

| Config | Recall | Precision | F1 | FPR | Mean latency (ms) | p95 latency (ms) |
|---|---|---|---|---|---|---|
| a_regex_fuzzy | 6.4% | 100.0% | 0.120 | 0.0% | 1.2 | 2.4 |
| b_regex_fuzzy_llm | 48.7% | 100.0% | 0.655 | 0.0% | 1536.5 | 2462.4 |
| c_regex_fuzzy_finetuned | 24.4% | 95.0% | 0.388 | 0.8% | 53.7 | 127.2 |
| d_all_stages | 50.0% | 97.5% | 0.661 | 0.8% | 1589.7 | 2517.5 |
| e_finetuned_only | 21.8% | 94.4% | 0.354 | 0.8% | 53.2 | 130.1 |

### test_300 (n=300)

| Config | Recall | Precision | F1 | FPR | Mean latency (ms) | p95 latency (ms) |
|---|---|---|---|---|---|---|
| a_regex_fuzzy | 17.7% | 52.8% | 0.265 | 17.6% | 5.1 | 19.3 |
| b_regex_fuzzy_llm | 63.9% | 78.3% | 0.704 | 19.7% | 1595.7 | 2433.0 |
| c_regex_fuzzy_finetuned | 92.4% | 83.9% | 0.879 | 19.7% | 146.5 | 327.0 |
| d_all_stages | 97.5% | 83.7% | 0.901 | 21.1% | 1733.8 | 2648.1 |
| e_finetuned_only | 90.5% | 96.0% | 0.932 | 4.2% | 138.2 | 302.5 |

### test_full (n=912)

| Config | Recall | Precision | F1 | FPR | Mean latency (ms) | p95 latency (ms) |
|---|---|---|---|---|---|---|
| a_regex_fuzzy | 22.4% | 64.6% | 0.332 | 12.3% | 4.7 | 17.1 |
| c_regex_fuzzy_finetuned | 95.2% | 86.3% | 0.905 | 15.1% | 124.9 | 290.5 |
| e_finetuned_only | 92.5% | 95.3% | 0.939 | 4.6% | 119.4 | 275.6 |
