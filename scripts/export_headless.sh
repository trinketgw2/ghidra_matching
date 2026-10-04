#!/usr/bin/env bash
# Export matching data (functions/data CSV + meta JSON) with Ghidra's headless analyzer.
#
# Requires GHIDRA_INSTALL_DIR (the folder that contains support/analyzeHeadless).
# Close the project in the Ghidra GUI first: headless mode cannot open a locked project.
#
# 1) Program already in a Ghidra project (typical for the marked-up source build):
#      scripts/export_headless.sh project <project_dir> <project_name> <program_path> <out_dir> [label]
#    program_path is the path inside the project, e.g. /game_v1.0.exe or /builds/game.exe.
#    The project is opened read-only; nothing is saved.
#
# 2) Raw binary (imported + auto-analysed into a throwaway project):
#      scripts/export_headless.sh import <binary> <out_dir> [label]
#
# Extra analyzeHeadless options can be passed via GHIDRA_HEADLESS_OPTS,
# e.g. GHIDRA_HEADLESS_OPTS="-processor x86:LE:32:default -cspec windows".
set -euo pipefail

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[[ "${1:-}" == project || "${1:-}" == import ]] || usage

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra installation folder}"
HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
[[ -x "$HEADLESS" ]] || { echo "analyzeHeadless not found at $HEADLESS" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../ghidra_scripts" && pwd)"
read -r -a EXTRA <<< "${GHIDRA_HEADLESS_OPTS:-}"

mode="${1:-}"; shift || true
case "$mode" in
  project)
    [[ $# -ge 4 ]] || usage
    proj_dir="$1"; proj_name="$2"; program="$3"; out_dir="$(mkdir -p "$4" && cd "$4" && pwd)"
    label="${5:-$(basename "$program")}"
    folder="$(dirname "$program")"; file="$(basename "$program")"
    [[ "$folder" == "/" || "$folder" == "." ]] && folder=""
    "$HEADLESS" "$proj_dir" "$proj_name$folder" -process "$file" -readOnly -noanalysis \
      -scriptPath "$SCRIPT_DIR" ${EXTRA[@]+"${EXTRA[@]}"} \
      -postScript ExportMatchData.java "$out_dir" "$label" 2>&1 \
      | tee "$out_dir/$label.export.log" | grep -E "ExportMatchData|ERROR|Exception" || true
    ;;
  import)
    [[ $# -ge 2 ]] || usage
    binary="$1"; out_dir="$(mkdir -p "$2" && cd "$2" && pwd)"; label="${3:-$(basename "$binary")}"
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    "$HEADLESS" "$tmp" export_tmp -import "$binary" -scriptPath "$SCRIPT_DIR" ${EXTRA[@]+"${EXTRA[@]}"} \
      -postScript ExportMatchData.java "$out_dir" "$label" -deleteProject 2>&1 \
      | tee "$out_dir/$label.export.log" | grep -E "ExportMatchData|ERROR|Exception" || true
    ;;
  *) usage ;;
esac

[[ -f "$out_dir/$label.functions.csv" ]] || { echo "export failed, see $out_dir/$label.export.log" >&2; exit 1; }
rm -f "$out_dir/$label.export.log"
echo "exported $out_dir/$label.{functions.csv,data.csv,meta.json}"
