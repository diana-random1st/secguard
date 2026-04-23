---
language: en
license: apache-2.0
tags:
  - security
  - shell-commands
  - safety-classifier
  - gguf
  - qwen3.5
datasets:
  - ML4Net/SSH-Shell-Attacks
  - TellinaTool/nl2bash
pipeline_tag: text-classification
---

# secguard-guard — Shell Command Safety Classifier

Binary classifier for shell commands: **safe** vs **destructive**.

## Model Details

| Property | Value |
|----------|-------|
| Base model | [Qwen/Qwen3.5-0.8B](https://huggingface.co/Qwen/Qwen3.5-0.8B) |
| Fine-tuning | LoRA (rank 16, α=32, 4.26M trainable / 752M total) |
| Quantization | Q8_0 (GGUF) |
| Size | ~800 MB |
| Context | 512 tokens |
| Inference | llama.cpp / llama-cpp-rs |

## Training

- **Dataset**: 21,430 labeled examples (balanced 50/50, ChatML format)
  - **Destructive** (10,715): SSH-Shell-Attacks honeypot commands (ML4Net, 408K sessions) + synthetic SaaS CLI patterns
  - **Safe** (10,715): NL2Bash corpus (12.6K real admin commands) + synthetic dev/ops commands
- **Method**: MLX LoRA, 16 layers, batch 4, lr 1e-5, 1000 iterations
- **Loss**: Train 0.393, Val 0.401 (best at iter 400)
- **Test accuracy**: 98.8% (500 held-out examples; precision 99.2%, recall 98.4%, F1 0.988)
- **Hardware**: Apple Silicon M3 Max, ~30 minutes training

## Notes on inference

Qwen3.5 reasoning models emit `<think>…</think>` blocks before the final answer.
The runtime (`secguard-brain`) strips the thinking block via `rfind("</think>")`
before matching the label, so the model is used as a classifier without
retraining to suppress reasoning.

The MLX → GGUF pipeline requires three post-processing fixes for Qwen3.5
(tensor name rename, conv1d transpose, norm −1). Without them, the model
produces multilingual token salad. This GGUF was produced through the fixed
pipeline.

## What it detects

Commands the model learns to classify as **destructive**:
- File deletion (rm -rf, find -delete, shred)
- Git history rewriting (push --force, reset --hard, rebase, filter-branch)
- Database destruction (DROP TABLE, FLUSHALL, db.dropDatabase())
- Cloud resource deletion (aws s3 rm, gcloud delete, terraform destroy)
- Remote code execution (curl | bash, wget | sh)
- Container/k8s cleanup (docker system prune, kubectl delete namespace)
- SaaS destructive ops (stripe cancel, heroku apps:destroy)

## Usage with secguard

This model is Phase 3 (ML brain) in secguard's three-phase guard:
1. **Policy allowlist** — known-safe commands (zero latency)
2. **Heuristic rules** — 40+ regex patterns (zero latency)
3. **ML brain** — this model (catches what rules miss)

```bash
secguard model     # downloads this GGUF to ~/.secguard/models/
secguard init --global     # installs Claude Code / Gemini / Codex hooks
```

## Limitations

- Trained on English commands only
- SSH honeypot data doesn't represent all attack vectors
- Confidence threshold: 0.85 (tunable in secguard config)
- Below threshold → verdict falls through to safe (heuristic stays as backstop)

## License

Apache 2.0
