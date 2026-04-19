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

# secguard-guard -- Shell Command Safety Classifier

Binary classifier for shell commands: **safe** vs **destructive**.

## Model Details

| Property | Value |
|----------|-------|
| Base model | [Qwen/Qwen3.5-2B](https://huggingface.co/Qwen/Qwen3.5-2B) |
| Fine-tuning | LoRA (rank 8, 2.8M trainable params / 1.88B total) |
| Quantization | Q8_0 (GGUF) |
| Size | 1.9 GB |
| Context | 512 tokens |
| Inference | llama.cpp / llama-cpp-rs |

## Training

- **Dataset**: 21,430 labeled examples (balanced 50/50)
  - **Destructive** (10,715): SSH-Shell-Attacks honeypot commands (ML4Net, 408K sessions) + synthetic SaaS CLI patterns
  - **Safe** (10,715): NL2Bash corpus (12.6K real admin commands) + synthetic dev/ops commands
- **Method**: MLX LoRA, 8 layers, batch 4, lr 5e-5, 400 iterations
- **Loss**: Train 0.388, Val 0.394
- **Hardware**: Apple Silicon (M-series), ~12 minutes training

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
1. **Policy allowlist** -- known-safe commands (zero latency)
2. **Heuristic rules** -- 40+ regex patterns (zero latency)
3. **ML brain** -- this model (catches what rules miss)

```bash
secguard model
```

## Limitations

- Trained on English commands only
- SSH honeypot data may not represent all attack vectors
- Confidence threshold: 85% (tunable in secguard config)

## License

Apache 2.0
