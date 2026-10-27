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
TMP_RULES="$(mktemp "${TMPDIR:-/tmp}/agent-pkg-audit-rules.XXXXXX.json")"
trap 'rm -f "$TMP_RULES"' EXIT

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
$PY "$ROOT/lib/audit_core.py" "$ROOT" --exclude fixtures >/dev/null 2>&1
check "package passes its own gate" 0 $?

echo "== 4. custom project rules =="
cat > "$TMP_RULES" << 'JSON'
{
  "_comment": "documentation key must be ignored, not crash",
  "persona": [
    { "id": "p1", "severity": "blocker", "pattern": "reviewer@" }
  ]
}
JSON
out=$($PY "$ROOT/lib/audit_core.py" "$ROOT/test/fixtures/dirty-pkg" --rules "$TMP_RULES" 2>&1)
code=$?
check "custom rules file loads without crashing" 1 $code
if printf '%s' "$out" | grep -q "p1"; then
  echo "  PASS  custom rule is applied"
  pass=$((pass + 1))
else
  echo "  FAIL  custom rule was not applied"
  fail=$((fail + 1))
fi

echo "== 5. whole-repo scan =="
# The dirty fixture has no agents/ directory at its root, yet its content
# must still be scanned. This regression guards the "scan the whole repo"
# behaviour.
if printf '%s' "$out" | grep -q "assistant.md"; then
  echo "  PASS  files outside agents/ are still scanned"
  pass=$((pass + 1))
else
  echo "  FAIL  whole-repo scan missed a file"
  fail=$((fail + 1))
fi

echo "== 6. npm pack =="
if command -v npm >/dev/null 2>&1; then
  (cd "$ROOT" && npm pack --dry-run >/dev/null 2>&1)
  check "npm pack succeeds" 0 $?
else
  echo "  SKIP  npm not on PATH"
fi

echo ""
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] || exit 1
