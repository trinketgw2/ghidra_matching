#!/usr/bin/env bash
# End-to-end check of `ghidra-match update` against a real Ghidra installation:
#   v1 (with simulated user markup) in project folder /src, then the "installed" exe is
#   replaced by v2 (a game update) and `update src --new` must import, analyse, export and
#   pair it; `--existing` and the unchanged-exe guard are checked too.
#
#   GHIDRA_INSTALL_DIR=/opt/ghidra tests/integration/run_update.sh [work_dir]
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mkdir -p "${1:-$ROOT/out/integration_update}" && cd "${1:-$ROOT/out/integration_update}" && pwd)"
HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
CXX="${CXX:-g++}"
CXXFLAGS="-O1 -g -fno-pie -no-pie -fno-omit-frame-pointer"

rm -rf "$WORK"/{install,proj,exports,out,v2}; mkdir -p "$WORK"/{install,proj,v2}
cd "$WORK"
$CXX $CXXFLAGS -o install/sample "$ROOT/tests/integration/sample.cpp"
$CXX $CXXFLAGS -DV2 -o v2/sample "$ROOT/tests/integration/sample.cpp" && strip v2/sample

echo "== v1 into /src with user markup"
"$HEADLESS" proj pipe/src -import install/sample > import.log 2>&1 || { tail -40 import.log; exit 1; }
"$HEADLESS" proj pipe/src -process sample -noanalysis -scriptPath "$ROOT/tests/integration" \
  -postScript MarkupSource.java 2>&1 | grep -E "MarkupSource>|ERROR" || true

run_update() {
  ghidra-match update "$@" --ghidra "$GHIDRA_INSTALL_DIR" --project-dir proj --project-name pipe \
    --program sample --exports exports --out out
}

echo "== unchanged exe must be refused"
if run_update src --new; then echo "FAIL: unchanged exe was imported"; exit 1; fi

echo "== game update: --new picks up the replaced exe"
cp v2/sample install/sample
run_update src --new --name new1 | tee new1.log
test -f out/pairs_src_to_new1.csv
names=$(grep -c ",function,.*,name" out/pairs_src_to_new1.csv || true)
names=$(awk -F, '$1=="function" && $8 ~ /name/' out/pairs_src_to_new1.csv | wc -l)
echo "function pairs carrying a user name: $names"
[[ "$names" -ge 15 ]] || { echo "FAIL: expected >= 15 named functions"; exit 1; }
grep -q "AnalyzeWithProgress.java> \[.*Analysis finished" out/logs/import_new1.log \
  || { echo "FAIL: no analysis progress in log"; exit 1; }
grep -q "^    \[.*\] Analysis finished" new1.log \
  || { echo "FAIL: analysis progress not shown on the console"; exit 1; }

echo "== --existing reuses the folder"
run_update src --existing new1 > existing.log
grep -q "Existing build new1" existing.log || { echo "FAIL: --existing"; exit 1; }

echo "== new folder that already exists is refused"
if run_update src --new v2/sample --name new1 --force; then echo "FAIL: overwrote new1"; exit 1; fi
echo "OK"
