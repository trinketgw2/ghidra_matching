#!/usr/bin/env bash
# Apply a pairing table to a target program with Ghidra's headless analyzer.
#
# Requires GHIDRA_INSTALL_DIR. Source and target must be in the same Ghidra project, and the
# project must not be open in the Ghidra GUI. Changes to the target are saved to the project.
#
#   scripts/apply_headless.sh <project_dir> <project_name> <target_program> <pairs.csv> \
#       <source_program> [key=value ...]
#
# Program paths are paths inside the project, e.g. /game_v1.1.exe.
# Options (see ghidra_scripts/ApplyMatchTable.java): min_confidence=0.5 names=true
# signatures=true data=true copy_all_types=false conflict=replace_empty overwrite=false
# dry_run=false report=<file.csv>
set -euo pipefail

[[ $# -ge 5 ]] || { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra installation folder}"
HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../ghidra_scripts" && pwd)"

proj_dir="$1"; proj_name="$2"; target="$3"; pairs="$(cd "$(dirname "$4")" && pwd)/$(basename "$4")"
source_program="$5"; shift 5

folder="$(dirname "$target")"; file="$(basename "$target")"
[[ "$folder" == "/" || "$folder" == "." ]] && folder=""

"$HEADLESS" "$proj_dir" "$proj_name$folder" -process "$file" -noanalysis \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ApplyMatchTable.java "$pairs" "$source_program" "$@" 2>&1 \
  | grep -E "ApplyMatchTable|ERROR|Exception|^  [a-z_]+: [0-9]+" || true
