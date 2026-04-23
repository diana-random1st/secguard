#!/bin/bash
# Evaluate secguard-guard GGUF against test.jsonl.
# Runs every line through ~/bin/secguard guard and compares verdict to label.
# Outputs: accuracy, precision, recall, confusion matrix.
set -e

MODEL_PATH="${1:-$HOME/.secguard/models/secguard-guard.gguf}"
TEST_FILE="${2:-$HOME/Projects/secguard/training/splits/test.jsonl}"
SAMPLE="${3:-all}"  # "all" or integer

if [ ! -f "$MODEL_PATH" ]; then
  echo "model not found: $MODEL_PATH" >&2; exit 1
fi
if [ ! -f "$TEST_FILE" ]; then
  echo "test file not found: $TEST_FILE" >&2; exit 1
fi

# Back up currently-installed model if different
INSTALLED=~/.secguard/models/secguard-guard.gguf
if [ "$MODEL_PATH" != "$INSTALLED" ]; then
  [ -f "$INSTALLED" ] && mv "$INSTALLED" "${INSTALLED}.eval-bak"
  cp "$MODEL_PATH" "$INSTALLED"
fi

python3 - "$TEST_FILE" "$SAMPLE" <<'PY'
import json, subprocess, sys, time
from collections import Counter

test_file = sys.argv[1]
sample = sys.argv[2]

items = []
with open(test_file) as f:
    for line in f:
        d = json.loads(line)
        user = next(m["content"] for m in d["messages"] if m["role"] == "user")
        label = next(m["content"] for m in d["messages"] if m["role"] == "assistant").strip().lower()
        if label in ("safe", "destructive"):
            items.append((user, label))

if sample != "all":
    import random
    random.seed(42)
    random.shuffle(items)
    items = items[:int(sample)]

print(f"Evaluating {len(items)} examples...", file=sys.stderr)

cm = Counter()  # (predicted, actual) → count
latencies = []
errors = 0
t0 = time.time()

for i, (cmd, expected) in enumerate(items):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}, "hook_event_name": "PreToolUse"})
    try:
        t1 = time.time()
        r = subprocess.run(
            ["/Users/random1st/bin/secguard", "hook", "guard", "--target", "claude"],
            input=payload, capture_output=True, text=True, timeout=30,
        )
        latencies.append(time.time() - t1)
        # verdict appears in stdout as JSON {"decision":"ask",...} for destructive,
        # empty/minimal for safe. Telemetry is authoritative — read last line.
        predicted = "destructive" if '"decision":"ask"' in r.stdout else "safe"
    except Exception as e:
        errors += 1
        predicted = "safe"  # fail-safe
    cm[(predicted, expected)] += 1
    if (i + 1) % 100 == 0:
        print(f"  {i+1}/{len(items)}  avg latency {sum(latencies)/len(latencies)*1000:.0f}ms", file=sys.stderr)

dt = time.time() - t0
n = len(items)
tp = cm[("destructive", "destructive")]
tn = cm[("safe", "safe")]
fp = cm[("destructive", "safe")]
fn = cm[("safe", "destructive")]

acc = (tp + tn) / n if n else 0
prec = tp / (tp + fp) if (tp + fp) else 0
rec = tp / (tp + fn) if (tp + fn) else 0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0

print(f"\n=== RESULTS ({n} examples, {dt:.0f}s total, {errors} errors) ===")
print(f"Accuracy:  {acc:.3f}")
print(f"Precision: {prec:.3f}  (destructive predictions correct)")
print(f"Recall:    {rec:.3f}  (destructive actuals caught)")
print(f"F1:        {f1:.3f}")
print(f"Latency:   avg {sum(latencies)/len(latencies)*1000:.0f}ms  max {max(latencies)*1000:.0f}ms")
print(f"\nConfusion matrix (rows=predicted, cols=actual):")
print(f"                 safe    destructive")
print(f"  safe         {cm[('safe','safe')]:>6}  {cm[('safe','destructive')]:>10}")
print(f"  destructive  {cm[('destructive','safe')]:>6}  {cm[('destructive','destructive')]:>10}")
PY

# Restore original
if [ "$MODEL_PATH" != "$INSTALLED" ] && [ -f "${INSTALLED}.eval-bak" ]; then
  mv "${INSTALLED}.eval-bak" "$INSTALLED"
fi
