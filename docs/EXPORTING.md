# Exporting builds from Ghidra

The matcher works on exports, three small files per build that share a prefix, the build's
label:

| File | Contents |
|------|----------|
| `<label>.functions.csv` | one row per function: address, size, vtable slots, referenced strings, callees and more |
| `<label>.data.csv` | one row per string, vtable, and global that is labelled or referenced by code |
| `<label>.meta.json` | program name, image base, language, executable hashes, Ghidra version |

They go to your export folder (`EXPORT_DIR` in `user_preferences.cfg`, `exports` by
default), which git ignores. [csv_format.md](csv_format.md) describes every column.

The scripts are tested with Ghidra 12.1.3, which needs Java 21.

## Before exporting

1. Analyse each program fully with the default analyzers. For C++ programs, leave the RTTI
   analyzers on (*Windows x86 PE RTTI Analyzer* for MSVC; *GCC RTTI* and *Demangler GNU*
   for GCC and Clang). They label vtables as `Class::vftable`, which the matcher can pair
   by name even when the program has no symbols.
2. Use the same analysis options for every build. Different options give different
   function boundaries and string definitions, and the matcher finds fewer pairs.
   `update.bat --new` and `AnalyzeWithProgress.java` copy the options from the older build
   for you.
3. Export the source build, the one with your markup, as it is.
4. The target build should be imported and analysed, without manual work yet. Markup
   already in it is kept when you apply, unless you ask otherwise.

## In the Ghidra GUI

1. Open *Window → Script Manager*, click *Manage Script Directories* (the icon with the
   bulleted list) and add the repository's `ghidra_scripts` folder. This is needed once.
2. Open the build in the CodeBrowser.
3. Run `ExportMatchData.java` from the *Matching* category.
4. When asked, pick your export folder and enter the build's folder name in the project
   as the label, for example `v1.1`.

## With export.bat (Windows)

With `user_preferences.cfg` filled in (see the README), this exports one build without
opening the GUI:

```bat
scripts\windows\export.bat v1.1
scripts\windows\export.bat MyProject/v1.1/program.exe
```

The first form needs `GHIDRA_PROJECT_NAME` and `PROGRAM_NAME` in the preferences; the
second names the project and program directly. Close the project in the Ghidra GUI first.
If the output says "Unable to lock project", it is still open: use *File → Close Project*
or exit Ghidra.

`export.bat` runs Ghidra's headless launcher like this:

```bat
"%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat" C:\path\to\projects MyProject/v1.1 -process program.exe -readOnly -noanalysis -scriptPath %CD%\ghidra_scripts -postScript ExportMatchData.java %CD%\exports v1.1
```

The first argument is the folder that contains `MyProject.gpr`. The second is the project
name followed by the build's folder; `-process` takes only the program name. `-readOnly`
means nothing in the project is changed.

When you set variables by hand in `cmd`, put the quotes around the whole assignment,
`set "NAME=value"`. With `set NAME="value"`, the quotes become part of the value.

## Headless on Linux and macOS

Set `GHIDRA_INSTALL_DIR` to the Ghidra folder (the one that contains `support/`) and
close the project in the GUI.

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.3_PUBLIC

# A program already in a project; opened read-only, nothing is saved
scripts/export_headless.sh project ~/ghidra_projects MyProject /v1.1/program exports v1.1

# A program file; imported and analysed in a temporary project that is deleted afterwards
scripts/export_headless.sh import ~/builds/v1.2/program exports v1.2
```

In `project` mode the program path is its path inside the Ghidra project, as the project
window shows it. If Ghidra cannot identify a program file by itself, pass loader options,
for example
`GHIDRA_HEADLESS_OPTS="-processor x86:LE:32:default -cspec windows" scripts/export_headless.sh import ...`.

## Checking an export

```bat
ghidra-match info exports\v1.0 exports\v1.1
```

Things to look at:

- `functions` should be in the range you expect for the program.
- `functions_with_strings` and `functions_in_vtables` should not be zero for a C++
  program.
- `functions_user_named`, `functions_user_signature` and `data_user_named` should roughly
  match the markup you did in the source build. `functions_named` is higher because it
  also counts imports, library functions and names from analysis.

## Notes

- Exports contain function names, string literals and addresses from the program, but no
  code bytes. Share them only where you are allowed to.
- Git ignores executables, packed programs (`programs/`, `*.gzf`) and Ghidra project
  files.
- When `ExportMatchData.java` changes its format, `format_version` in `meta.json` goes
  up, and you should export again. Format 1 exports can still be paired, but they do not
  record who set a name, so names Ghidra generated would also land in the pairing table.
- To measure how well the matcher does on your builds, see "Checking the matcher on your
  builds" in the README.
