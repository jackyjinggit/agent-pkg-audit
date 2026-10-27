#!/usr/bin/env bash
# agent-pkg-audit · test suite
# ---------------------------------------------------------------
# Three assertions, all offline, no dependencies:
#   1. clean fixture  -> exit 0
#   2. dirty fixture  -> exit 1, and each injected defect is named
#   3. self audit     -> exit 0 (the tool passes its own gate)
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-py -3}"
if ! $PY --version >/dev/null 2>&1; then
  PY="${PYTHON:-python3}"
fi

pass=0
fail=0

check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  PASS  $label (exit $actual)"
    pass=$((pass + 1))
  else
    echo "  FAIL  $label (expected exit $expected, got $actual)"
    fail=$((fail + 1))
  fi
}

echo "== 1. clean fixture =="
$PY "$ROOT/lib/audit_core.py" "$ROOT/test/fixtures/clean-pkg" >/dev/null 2>&1
check "clean package exits 0" 0 $?

echo "== 2. dirty fixture =="
out=$($PY "$ROOT/lib/audit_core.py" "$ROOT/test/fixtures/dirty-pkg" 2>&1)
code=$?
check "dirty package exits 1" 1 $code

for defect in "manifest missing keys" "email address" "absolute Windows path" "hard-coded secret" "unfinished marker" "does not exist"; do
  if printf '%s' "$out" | grep -q "$defect"; then
    echo "  PASS  detects: $defect"
    pass=$((pass + 1))
  else
    echo "  FAIL  misses: $defect"
    fail=$((fail + 1))
  fi
done

echo "== 3. self audit =="
$PY "$ROOT/lib/audit_core.py" "$ROOT" >/dev/null 2>&1
check "package passes its own gate" 0 $?

echo "== 4. npm pack =="
if command -v npm >/dev/null 2>&1; then
  (cd "$ROOT" && npm pack --dry-run >/dev/null 2>&1)
  check "npm pack succeeds" 0 $?
else
  echo "  SKIP  npm not on PATH"
fi

echo ""
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] || exit 1
