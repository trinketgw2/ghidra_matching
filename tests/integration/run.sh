#!/usr/bin/env bash
# End-to-end check of the whole pipeline against a real Ghidra installation:
#   build sample v1 (with DWARF symbols) and v2 (stripped) -> import + analyse -> export both
#   -> ghidra-match pair -> eval against unstripped v2 -> apply to v2 -> re-export -> verify.
#
#   GHIDRA_INSTALL_DIR=/opt/ghidra tests/integration/run.sh [work_dir]
#
# Needs g++ (or CXX), strip, Java 21 and the ghidra-match CLI (pip install -e .).
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mkdir -p "${1:-$ROOT/out/integration}" && cd "${1:-$ROOT/out/integration}" && pwd)"
HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
CXX="${CXX:-g++}"
CXXFLAGS="-O1 -g -fno-pie -no-pie -fno-omit-frame-pointer"

rm -rf "$WORK"/{bin,exports,proj}; mkdir -p "$WORK"/{bin,exports,proj}
cd "$WORK"

echo "== build"
$CXX $CXXFLAGS -o bin/sample_v1 "$ROOT/tests/integration/sample.cpp"
$CXX $CXXFLAGS -DV2 -o bin/sample_v2_truth "$ROOT/tests/integration/sample.cpp"
cp bin/sample_v2_truth bin/sample_v2 && strip bin/sample_v2

echo "== import + analyse"
"$HEADLESS" proj sample -import bin/sample_v1 bin/sample_v2 > import.log 2>&1 \
  || { tail -40 import.log; exit 1; }

echo "== simulate user markup on v1"
"$HEADLESS" proj sample -process sample_v1 -noanalysis -scriptPath "$ROOT/tests/integration" \
  -postScript MarkupSource.java 2>&1 | grep -E "MarkupSource|ERROR|Exception" || true

dump() { # dump <program> <out.csv>
  "$HEADLESS" proj sample -process "$1" -readOnly -noanalysis \
    -scriptPath "$ROOT/tests/integration" -postScript DumpMarkup.java "$WORK/$2" 2>&1 \
    | grep -E "ERROR|Exception" || true
}

echo "== export"
"$ROOT/scripts/export_headless.sh" project proj sample /sample_v1 exports v1
"$ROOT/scripts/export_headless.sh" project proj sample /sample_v2 exports v2
"$ROOT/scripts/export_headless.sh" import bin/sample_v2_truth exports v2_truth
ghidra-match info exports/v1 exports/v2

echo "== pair"
ghidra-match pair exports/v1 exports/v2 -o pairs.csv --unmatched unmatched.csv > pair_stats.json
cat pair_stats.json
cat pairs.csv

echo "== eval (all pairs, against unstripped v2 at the same addresses)"
ghidra-match pair exports/v1 exports/v2 -o pairs_all.csv --all > /dev/null
ghidra-match eval exports/v1 exports/v2_truth pairs_all.csv --show-wrong 20 | tee eval.json

echo "== apply"
dump sample_v1 v1.markup.csv
dump sample_v2 v2_before.markup.csv
"$ROOT/scripts/apply_headless.sh" proj sample /sample_v2 pairs.csv /sample_v1 \
  report="$WORK/apply_report.csv"
dump sample_v2 v2_after.markup.csv

echo "== verify"
python3 "$ROOT/tests/integration/check_applied.py" \
  v1.markup.csv v2_before.markup.csv v2_after.markup.csv pairs.csv
