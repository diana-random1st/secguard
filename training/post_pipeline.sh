#!/bin/bash
# Post-install finalization:
#   1. Run eval on held-out test set → capture accuracy
#   2. Parse train/val loss from training log
#   3. Fill MODEL_CARD.md placeholders (__TRAIN_LOSS__, __VAL_LOSS__, __ACC__, __N_TEST__, __TRAIN_MIN__)
#   4. Run publish_hf.sh (if --publish flag)
#
# Usage:
#   ./post_pipeline.sh                 # eval + fill, no upload
#   ./post_pipeline.sh --publish       # eval + fill + upload to HF
#   ./post_pipeline.sh --publish --sample 500    # faster eval
set -e
cd "$(dirname "$0")"

PUBLISH=0
SAMPLE=500
while [ $# -gt 0 ]; do
  case "$1" in
    --publish) PUBLISH=1; shift;;
    --sample) SAMPLE="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

TRAIN_LOG=$(ls -t logs/train-0.8b-*.log | head -1)
if [ ! -f "$TRAIN_LOG" ]; then
  echo "no training log found" >&2; exit 1
fi

# Parse best val loss + final train loss + duration
VAL_LOSS=$(grep "Val loss" "$TRAIN_LOG" | awk '{print $(NF-2)}' | tr -d ',' | sort -n | head -1)
TRAIN_LOSS=$(grep "Train loss" "$TRAIN_LOG" | tail -1 | awk '{print $5}' | tr -d ',')
START_TS=$(head -1 "$TRAIN_LOG" 2>/dev/null | awk '{print $1}' || echo "")
# estimate from file mtimes
DURATION_MIN=$(python3 -c "
import os, time
start = os.path.getctime('$TRAIN_LOG')
end = os.path.getmtime('$TRAIN_LOG')
print(round((end - start) / 60))
")

echo "=== Training summary ==="
echo "  train loss: $TRAIN_LOSS"
echo "  best val loss: $VAL_LOSS"
echo "  duration: ~${DURATION_MIN} min"

echo
echo "=== Running eval on $SAMPLE test examples ==="
EVAL_OUT=/tmp/secguard-eval-$(date +%s).out
./eval_model.sh ~/.secguard/models/secguard-guard.gguf splits/test.jsonl "$SAMPLE" 2>&1 | tee "$EVAL_OUT"
ACC=$(grep "^Accuracy:" "$EVAL_OUT" | awk '{print $2}')
N=$(grep "^=== RESULTS" "$EVAL_OUT" | awk '{print $3}' | tr -d '(,')
ACC_PCT=$(python3 -c "print(f'{float(\"$ACC\")*100:.1f}')")

echo
echo "=== Filling MODEL_CARD.md ==="
sed -i '' \
  -e "s/__TRAIN_LOSS__/$TRAIN_LOSS/g" \
  -e "s/__VAL_LOSS__/$VAL_LOSS/g" \
  -e "s/__ACC__/$ACC_PCT/g" \
  -e "s/__N_TEST__/$N/g" \
  -e "s/__TRAIN_MIN__/$DURATION_MIN/g" \
  MODEL_CARD.md

echo "filled values:"
grep -E "Train loss|Test accuracy|training" MODEL_CARD.md | head -5

if [ "$PUBLISH" -eq 1 ]; then
  echo
  echo "=== Publishing to HF ==="
  ./publish_hf.sh
fi

echo
echo "=== DONE ==="
echo "Model card: $(pwd)/MODEL_CARD.md"
[ "$PUBLISH" -eq 0 ] && echo "Re-run with --publish to upload to HF"
