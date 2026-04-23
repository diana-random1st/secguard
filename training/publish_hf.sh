#!/bin/bash
# Publish new GGUF + updated MODEL_CARD to huggingface.co/random1st/secguard-models.
# Requires:
#   - hf CLI authenticated (hf auth whoami → user=random1st)
#   - new GGUF at ~/.secguard/models/secguard-guard.gguf
#   - MODEL_CARD.md with placeholders filled
set -e

REPO=random1st/secguard-models
GGUF=~/.secguard/models/secguard-guard.gguf
CARD=~/Projects/secguard/training/MODEL_CARD.md

if ! hf auth whoami | grep -q "random1st"; then
  echo "not logged in as random1st" >&2; exit 1
fi
if [ ! -f "$GGUF" ]; then
  echo "GGUF missing: $GGUF" >&2; exit 1
fi
if grep -q "__TRAIN_LOSS__\|__VAL_LOSS__\|__ACC__" "$CARD"; then
  echo "MODEL_CARD.md has unfilled placeholders — fill before upload" >&2
  grep "__.*__" "$CARD"
  exit 1
fi

echo "=== uploading GGUF ($(du -h "$GGUF" | cut -f1)) ==="
hf upload "$REPO" "$GGUF" secguard-guard.gguf \
  --commit-message "Update to Qwen3.5-0.8B fine-tuned v4 (rank 16, 1000 iter, fixed MLX→GGUF pipeline)"

echo "=== uploading MODEL_CARD as README.md ==="
hf upload "$REPO" "$CARD" README.md \
  --commit-message "Update model card for v4 (Qwen3.5-0.8B, ~800MB Q8)"

echo "=== DONE. check: https://huggingface.co/$REPO ==="
