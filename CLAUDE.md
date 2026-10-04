# Notes for Claude / contributors

- Two halves: Ghidra-side Java scripts (`ghidra_scripts/`, run inside Ghidra 12.1.3) and the
  pure-Python matcher (`src/ghidra_matching/`, no Ghidra dependency, Python >= 3.9).
- The export format is a contract between `ExportMatchData.java`, `model.py` and
  `docs/csv_format.md`. Change all three together and bump `FORMAT_VERSION` in both code files.
- Matcher rule: pairs are strictly one-to-one and ambiguity means "no match". New heuristics
  should produce candidates and go through `Matcher._accept`.
- Checks: `pytest`, `ruff check .`, `ruff format --check .`.
- Java scripts: compile check with
  `javac -d /tmp/x -cp "$(find $GHIDRA_INSTALL_DIR/Ghidra -name '*.jar' | tr '\n' :)" ghidra_scripts/*.java`
  and the full pipeline with `GHIDRA_INSTALL_DIR=... tests/integration/run.sh`.
  Ghidra 12.1.3 download:
  https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip
- Personal settings live only in the gitignored `user_preferences.cfg` (template:
  `user_preferences.example.cfg`); never commit user paths, project names or program data.
  `exports/`, `out/` and `programs/` are local data folders and are ignored by git.
- Evaluate on real builds with `ghidra-match pair --blind --all` + `ghidra-match eval`
  (see `docs/EXPORTING.md`).
- The Windows batch files (`scripts/windows/`) must keep CRLF line endings. Avoid
  `call x.bat || ...` and one-line `( a & b )` blocks inside FOR loops; use
  `if errorlevel 1` and multi-line blocks. They can be smoke-tested on Linux with Wine
  (`wine cmd /c file.bat`) against a stub `analyzeHeadless.bat`.
