#!/bin/bash
set -e
LOG=logs/pipeline-$(date +%Y%m%d-%H%M%S).log
exec > "$LOG" 2>&1

echo "=== WAIT for training PID ==="
TRAIN_PID=$(cat /tmp/secguard-train.pid)
while kill -0 $TRAIN_PID 2>/dev/null; do sleep 5; done
echo "training exited, starting pipeline at $(date)"

echo "=== [1/4] mlx_lm.fuse ==="
uv run mlx_lm.fuse \
  --model Qwen/Qwen3.5-2B \
  --adapter-path adapters-2b \
  --save-path fused-model-2b

echo "=== [2/4] fix_mlx_fused_to_gguf.py ==="
uv run --with safetensors --with torch --with huggingface_hub \
  python ~/src/diana-router/fix_mlx_fused_to_gguf.py \
    fused-model-2b fused-model-2b-fixed \
    --base-model Qwen/Qwen3.5-2B

echo "=== [3/4] convert_hf_to_gguf.py (q8_0) ==="
uv run --with "numpy<2" --with torch --with transformers --with safetensors --with sentencepiece --with gguf --with protobuf \
  python ~/src/llama.cpp/convert_hf_to_gguf.py \
    fused-model-2b-fixed --outtype q8_0

echo "=== [4/4] install to ~/.secguard/models/ ==="
NEW_GGUF=$(ls -t fused-model-2b-fixed/*.gguf | head -1)
cp -v "$NEW_GGUF" ~/.secguard/models/secguard-guard.gguf.new
mv ~/.secguard/models/secguard-guard.gguf ~/.secguard/models/secguard-guard.gguf.bak
mv ~/.secguard/models/secguard-guard.gguf.new ~/.secguard/models/secguard-guard.gguf

echo "=== PIPELINE DONE at $(date) ==="
ls -la ~/.secguard/models/
