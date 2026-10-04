# ghidra_matching

Moves your Ghidra markup (function names, signatures, data labels, data types and
structures) from one build of a program to the next.

```
 build A (your markup)        build B (new)
        │                            │
  ExportMatchData.java        ExportMatchData.java        1. export   (Ghidra)
        │                            │
  A.functions.csv / A.data.csv  B.functions.csv / B.data.csv
        └───────────┬────────────────┘
             ghidra-match pair                              2. pair     (Python, no Ghidra)
                    │
               pairs.csv  (your marked-up items in A → address in B)
                    │
           ApplyMatchTable.java  (runs on B, reads markup from A)  3. apply  (Ghidra)
```

Tested with Ghidra 12.1.3 (Java 21) and Python 3.9 or later.

## What gets carried over

Only markup you made is transferred. Names that came from auto-analysis, imports, RTTI or
debug info (`FUN_…`, `switchD_…`, `caseD_…`, `ImgDelayDescr@…`, imported symbols,
`Class::vftable`) help the matcher find pairs, but they are never applied.

| Markup | When it is applied |
|--------|--------------------|
| Function name and namespace/class | The name was set by a user (`USER_DEFINED`). Missing classes and namespaces are created in the target. |
| Function signature | The signature was set by a user, or the function has a user-set name and an imported signature. This covers the return type, parameter names and types, calling convention, varargs and noreturn. Types used in the signature are copied too. |
| Data label and namespace | The label was set by a user. |
| Data type of a global | The global has a label you set. Structures, arrays and pointers are all fine. |
| Type definitions | Every structure, union, enum, typedef and function definition in the source program or in a project data type archive is copied first, including ones you have not applied anywhere yet (`copy_types=local`). |

Markup already in the target is kept. Default, analysis and AI names in the target are
replaced; names set by a user or imported there are replaced only with `overwrite=true`.
Thunks are skipped. With `report=<file.csv>`, every action and every skip is written to a
CSV file.

## Setup (Windows)

In `cmd`, from the repository folder:

```bat
python -m venv .venv
.venv\Scripts\activate.bat
pip install -e ".[dev]"
copy user_preferences.example.cfg user_preferences.cfg
notepad user_preferences.cfg
```

`user_preferences.cfg` holds your settings: where Ghidra is installed, the project folder
and name, the program name, the export and output folders, how new build folders are
named, and apply options you always want. Git ignores the file. The `.bat` files and
`ghidra-match update` read it. To keep it elsewhere, set `GHIDRA_MATCHING_CONFIG` to its
path.

Keep all builds in one Ghidra project, one project folder per build, for example
`/v1.0/program.exe` and `/v1.1/program.exe`. Applying needs the source and the
target in the same project.

### Naming a build

The scripts take a build as `<GhidraProjectPath>`, which can be written three ways:

| Argument | Means |
|----------|-------|
| `v1.1` | the folder; project and program come from `GHIDRA_PROJECT_NAME` and `PROGRAM_NAME` |
| `v1.1/program.exe` | the folder and the program; the project comes from `GHIDRA_PROJECT_NAME` |
| `MyProject/v1.1/program.exe` | the full path, for when the preferences do not name the project or program; nested folders work too (`MyProject/builds/v1.1/program.exe`) |

The last folder name (`v1.1`) is the build's label. Exports and pairing tables are
named after it.

## Workflow

### In the Ghidra GUI

First-time setup: open *Window → Script Manager*, click *Manage Script Directories* (the
icon with the bulleted list) and add the `ghidra_scripts` folder from this repository.
Ghidra remembers it, so you only do this once.

1. Export each build. Open it in the CodeBrowser and run `ExportMatchData.java` from the
   *Matching* category. Pick your export folder and give the build's folder name as the
   label.
2. Pair the two exports. This step needs no Ghidra:
   `scripts\windows\pair.bat <source GhidraProjectPath> <target GhidraProjectPath>`.
3. Apply. Open the target, run `ApplyMatchTable.java`, then choose the pairing table and
   the source program. Answer yes to the dry-run question the first time and read the
   report.

To analyse a new build with the same analysis options as an older one, open it and run
`AnalyzeWithProgress.java`; it asks which program to copy the options from.

### With the batch files

Close the project in the Ghidra GUI first; headless Ghidra cannot open a project that is
open elsewhere.

When a new build comes out, `update.bat` goes from the exe to the pairing table in one
command:

```bat
scripts\windows\update.bat <source GhidraProjectPath> --new [exe] [--name <folder>]
scripts\windows\update.bat <source GhidraProjectPath> --existing <target GhidraProjectPath>
```

```bat
scripts\windows\update.bat v1.0 --new
scripts\windows\update.bat v1.0 --new "D:\app\program.exe" --name v1.2
scripts\windows\update.bat v1.0 --existing v1.1
scripts\windows\update.bat MyProject/v1.0/program.exe --existing MyProject/v1.1/program.exe
```

It does three things:

1. Exports the source build, the one with your markup.
2. With `--new`, imports the exe into a new folder of the same project, copies the source
   build's analysis options, analyses it and exports it. Without an exe path it uses the
   file the source build was imported from, and without `--name` it names the folder
   after today's date using `BUILD_NAME_FORMAT`. While analysis runs it prints the current
   analyzer, its progress and the elapsed time, and a status line at least every 30
   seconds. It stops if the exe is identical to the source's (there is no new build yet;
   `--force` overrides this) or if the folder already exists. With `--existing`, it
   exports that build.
3. Pairs the two builds, writes `pairs_<source>_to_<target>.csv`,
   `unmatched_<source>_to_<target>.csv` and `contenders_<source>_to_<target>.csv` to
   `OUT_DIR`, and prints the `apply.bat` commands to run next.

Started without arguments, or by double-clicking, it asks for what it needs. Full Ghidra
logs go to `OUT_DIR\logs\`. On any operating system the same command is
`ghidra-match update ...`.

The steps one at a time:

```bat
scripts\windows\export.bat v1.0
scripts\windows\export.bat v1.1
scripts\windows\pair.bat v1.0 v1.1
scripts\windows\apply.bat v1.0 v1.1
scripts\windows\apply.bat v1.0 v1.1 apply
```

`apply.bat` without a third argument is a dry run: it writes
`apply_report_<source>_to_<target>.csv` to `OUT_DIR` and changes nothing. With `apply` it
changes the target and saves it. Back up the project folder before the first real run.

The pairing table lists only items that carry your markup. Its `markup` column says what
will be transferred for each row (`name`, `signature`, `label`, `datatype`). The unmatched
file lists your marked-up items that found no partner in the new build.

The contenders file (`contenders_<source>_to_<target>.csv`) is for review. For each of
your marked-up functions that is unmatched or paired with a confidence below 0.5, it lists
up to five likely partners in the new build with a score from 0 to 1 and the reasons:
identical code or start of code, size, shared strings and call arguments, paired callers
and callees, and the distance from where the function is expected between its paired
neighbours. Rank 0 is the current pair, scored the same way, so you can see whether a
contender looks better. A contender that is already paired with another function says so.
The pairing table never uses contenders; if you pick one, add or change the row in the
pairing table yourself. With `ghidra-match pair`, ask for the file with
`--contenders <file>` (`--contender-threshold` and `--max-contenders` change the limits).

On Linux and macOS, `scripts/export_headless.sh` and `scripts/apply_headless.sh` wrap the
headless export and apply.

### Apply options

Options are `key=value` pairs. There are three places to set them:

- `APPLY_OPTIONS` in `user_preferences.cfg`, for options you always want. Separate them
  with spaces, no quotes:
  ```
  APPLY_OPTIONS=min_confidence=0.5 replace_signatures=false
  ```
- After the mode argument of `apply.bat` (`dry` or `apply`), one option per pair of
  quotes. The quotes are needed because `cmd` splits unquoted arguments at `=`. Options
  given here override `APPLY_OPTIONS`.
  ```bat
  scripts\windows\apply.bat v1.0 v1.1 dry "min_confidence=0.5"
  scripts\windows\apply.bat v1.0 v1.1 apply "min_confidence=0.5" "replace_signatures=false"
  scripts\windows\apply.bat v1.0 v1.1 apply "conflict=replace" "copy_types=used"
  ```
- After the source program path when you call `ApplyMatchTable.java` from
  `analyzeHeadless` yourself.

| Option | Default | Effect |
|--------|---------|--------|
| `min_confidence` | `0` | Skip pairs below this confidence. |
| `names`, `signatures`, `data` | `true` | Set to `false` to leave that kind of markup out. |
| `copy_types` | `local` | `local` copies every type defined in the source program or in one of the project's data type archives (for example the output of class recovery). `all` also copies types from file archives such as `windows_vs12_64`. `used` copies only the types the applied items need. |
| `conflict` | `keep` | What happens when the target already has a type with the same path. `keep` uses the target's type, so no `.conflict` copies appear; empty placeholder structures in the target are still filled in from the source. `replace` overwrites the target's type with the source's. `rename` adds the source's type as `<name>.conflict`. |
| `replace_signatures` | `true` | When the target function already has the source's name (with or without its class), or both still have default `FUN_…` names, apply the source signature even if a user set the target's. The report shows the prototype that was replaced. |
| `fix_namespaces` | `true` | When the target function has the source's name but not its class or namespace (`SetCameraState` instead of `WvContext::SetCameraState`), add the class or namespace. |
| `overwrite` | `false` | Also replace names and signatures in the target that a user set or that were imported. |
| `user_only` | `true` | With `false`, any non-default markup is transferred, including names from analysis and imports. |
| `dry_run` | `false` | Only write the report. `apply.bat` sets this unless you pass `apply`. |
| `report` | none | CSV file with one row per action or skip. `apply.bat` sets this. |

## How matching works

Every pair is one-to-one. A candidate pair is accepted only if neither of its two items
has another candidate in the same step, so an ambiguous function stays unmatched and is
never guessed. All functions and data items take part, because unnamed neighbours are
what lead the matcher to your marked-up functions.

1. Anchors. Identical names that occur once in each build (imports, RTTI
   `Class::vftable` labels); identical sets of referenced strings; identical
   instruction-mnemonic hash and size; identical sets of strings and constants passed to
   the same call, such as the file path and line in
   `errorContext("expr", "D:\…\List.h", 0x9d)`; strings referenced by exactly one function
   in each build; string values that occur once (for data).
2. Propagation, repeated until nothing changes. A vtable is paired when its already
   paired slot functions point to one vtable in the other build, and then its remaining
   slots are paired by index. A paired function's only unmatched callee or caller is
   paired, and callee lists of the same shape are paired by position. The same happens
   for data referenced by paired functions, and for the single function that references
   a paired data item. For each source file path that functions report (with a line
   number), the functions are sorted by line in both builds, and runs of unpaired ones
   between paired ones are paired in line order. Functions paired this way must have
   similar sizes (`--size-ratio`, default 3).
3. Neighbours, once the steps above stop finding pairs. Most functions keep their link
   order between builds. When two matched functions have the same number of unmatched
   functions between them in both builds, and those have similar sizes, they are paired
   in order. This finds small getters and wrappers that have no strings, no callers and
   no vtable slot. `--no-neighbors` turns it off.

Vtables and function-pointer tables often point to code that Ghidra never made into a
function, because nothing calls it directly. The export includes these code entries, so a
method you named in one build can be paired with the bare code label in the next;
applying creates the function there.

Confidence drops a little with each propagation step, so `min_confidence` can filter out
pairs reached through long chains.

Two builds of a 72,000-function x64 C++ program, two weeks apart: 79,297 of 79,974
functions and code entries were paired in about 40 seconds, including all 1,355 functions
with user markup. With names hidden from the matcher (`--blind`), it paired all 845
functions the user had named identically in both builds, all correctly. Between builds a
month apart it paired 561 of 563 correctly; in the two others the user had named different
copies of identical code in the two builds.

## Repository layout

| Path | Contents |
|------|----------|
| `ghidra_scripts/ExportMatchData.java` | writes `<label>.functions.csv`, `<label>.data.csv` and `<label>.meta.json` |
| `ghidra_scripts/ApplyMatchTable.java` | applies a pairing table from a source program to the current program |
| `ghidra_scripts/AnalyzeWithProgress.java` | runs auto-analysis with progress output, optionally with another program's analysis options |
| `src/ghidra_matching/` | the matcher and the `ghidra-match` command (`info`, `pair`, `eval`, `update`) |
| `scripts/windows/` | batch files: `update.bat`, `export.bat`, `pair.bat`, `apply.bat`, and the helpers `config.bat` and `resolve.bat` |
| `scripts/*.sh` | headless export and apply for Linux and macOS |
| `user_preferences.example.cfg` | template for your `user_preferences.cfg` |
| `exports/`, `out/`, `programs/` | your local data (exports; pairing tables, reports and logs; packed programs), ignored by git |
| `tests/` | unit tests (`pytest`) and end-to-end tests with real Ghidra in `tests/integration/` |
| `docs/EXPORTING.md` | how to produce exports |
| `docs/csv_format.md` | file formats |

## Checking the matcher on your builds

If both builds share names (imports, RTTI, debug symbols, or your own names in both),
hide the names from the matcher and score its pairs against them:

```bat
ghidra-match pair exports\v1.0 exports\v1.1 -o out\pairs_blind.csv --blind --all
ghidra-match eval exports\v1.0 exports\v1.1 out\pairs_blind.csv --show-wrong 20
```

## Development

```bash
pytest                                              # unit tests, no Ghidra needed
ruff check . && ruff format --check .
GHIDRA_INSTALL_DIR=... tests/integration/run.sh     # export, pair, apply, verify
GHIDRA_INSTALL_DIR=... tests/integration/run_update.sh
```

`tests/integration/run.sh` builds a small C++ program twice. Version 1 gets simulated
user markup: renamed functions, a user signature with a typedef, a retyped and relabelled
global, and a structure that is not applied anywhere. Version 2 is changed and stripped.
The script exports both, pairs them, applies the markup and checks that all of it arrived
and that nothing else in the target was renamed. `run_update.sh` checks `ghidra-match
update` with a simulated program update.
