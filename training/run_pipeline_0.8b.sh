#!/bin/bash
set -e
LOG=logs/pipeline-0.8b-$(date +%Y%m%d-%H%M%S).log
exec > "$LOG" 2>&1

echo "=== WAIT for training PID ==="
TRAIN_PID=$(cat /tmp/secguard-train-0.8b.pid)
while kill -0 $TRAIN_PID 2>/dev/null; do sleep 5; done
echo "training exited at $(date)"

echo "=== [1/4] mlx_lm.fuse ==="
uv run mlx_lm.fuse \
  --model Qwen/Qwen3.5-0.8B \
  --adapter-path adapters-0.8b \
  --save-path fused-model-0.8b

echo "=== [2/4] fix_mlx_fused_to_gguf.py ==="
uv run --with safetensors --with torch --with huggingface_hub \
  python ~/src/diana-router/fix_mlx_fused_to_gguf.py \
    fused-model-0.8b fused-model-0.8b-fixed \
    --base-model Qwen/Qwen3.5-0.8B

echo "=== [3/4] convert_hf_to_gguf.py (q8_0) ==="
uv run --with "numpy<2" --with torch --with transformers --with safetensors --with sentencepiece --with gguf --with protobuf \
  python ~/src/llama.cpp/convert_hf_to_gguf.py \
    fused-model-0.8b-fixed --outtype q8_0

echo "=== [4/4] install to ~/.secguard/models/ ==="
NEW_GGUF=$(ls -t fused-model-0.8b-fixed/*.gguf | head -1)
du -h "$NEW_GGUF"
cp -v "$NEW_GGUF" ~/.secguard/models/secguard-guard.gguf.new
mv ~/.secguard/models/secguard-guard.gguf ~/.secguard/models/secguard-guard-2b.gguf.bak
mv ~/.secguard/models/secguard-guard.gguf.new ~/.secguard/models/secguard-guard.gguf
ls -la ~/.secguard/models/
echo "=== PIPELINE DONE at $(date) ==="
