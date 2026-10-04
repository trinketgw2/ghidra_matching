"""`ghidra-match update`: bring a new or existing build up to the pairing table in one go.

    source build (has your markup)          target build
    ------------------------------          -----------------------------------------------
    export                                  new:      import exe into /<name>/, analyse it
                                                      with the source's analysis options,
                                                      export
                                            existing: export
                        └──────── pair ────────┘

Ghidra runs headless, so the project must be closed in the Ghidra GUI. Paths come from the
command line, environment variables or user_preferences.cfg (see
user_preferences.example.cfg).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .config import REPO, Preferences
from .matcher import MatchConfig, match
from .model import load_build
from .pairing import write_pairs, write_unmatched

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

#: Headless output lines worth showing; everything goes to the log file.
_SHOW = re.compile(
    r"(AnalyzeWithProgress|ExportMatchData)\.java>|ERROR|Exception|IMPORTING:|Import succeeded|"
    r"Save succeeded|conflicting|Unable to lock"
)


#: Analyzer timing table printed at the end of analysis (matches "Exception" otherwise).
_HIDE = re.compile(r"\d+\.\d+ secs\s*$")


class PipelineError(RuntimeError):
    pass


@dataclass
class Settings:
    ghidra: Path
    project_dir: Path
    exports: Path
    out: Path
    project_name: Optional[str] = None
    program: Optional[str] = None
    build_name_format: str = "{year}-{month:02d}-{day:02d}"

    @property
    def headless(self) -> Path:
        name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        return self.ghidra / "support" / name


@dataclass(frozen=True)
class BuildRef:
    """A program in the Ghidra project: <project>:/<folder>/<program>."""

    project: str
    folder: str
    program: str

    @property
    def label(self) -> str:
        """Name used for exports and pairing tables: the last folder name."""
        return self.folder.rsplit("/", 1)[-1]

    @property
    def path(self) -> str:
        return f"/{self.folder}/{self.program}"

    def spec(self, project: Optional[str], program: Optional[str]) -> str:
        """Shortest argument that names this build again, given the configured defaults."""
        if self.project == project and self.program == program:
            return self.folder
        if self.project == project:
            return f"{self.folder}/{self.program}"
        return f"{self.project}/{self.folder}/{self.program}"


def parse_build(spec: str, project: Optional[str], program: Optional[str]) -> BuildRef:
    """Parse a build argument, like scripts/windows/resolve.bat.

    ``v1.1`` (project and program from the preferences), ``v1.1/program.exe``
    (project from the preferences) or ``Project/folder[/sub...]/program``.
    """
    parts = [p for p in spec.replace("\\", "/").split("/") if p]
    if not parts:
        raise PipelineError("No build given.")
    if len(parts) == 1:
        folder = parts[0]
    elif len(parts) == 2:
        folder, program = parts
    else:
        project, folder, program = parts[0], "/".join(parts[1:-1]), parts[-1]
    if not project:
        raise PipelineError(
            f'No project for "{spec}": set GHIDRA_PROJECT_NAME or pass Project/folder/program.'
        )
    if not program:
        raise PipelineError(f'No program for "{spec}": set PROGRAM_NAME or pass folder/program.')
    return BuildRef(project, folder, program)


def default_build_name(
    fmt: str = "{year}-{month:02d}-{day:02d}", today: Optional[_dt.date] = None
) -> str:
    """Folder name for a new build from BUILD_NAME_FORMAT and today's date."""
    d = today or _dt.date.today()
    return fmt.format(year=d.year, month=d.month, mon=MONTHS[d.month - 1], day=d.day)


def executable_from_meta(meta: dict) -> Optional[Path]:
    """Executable path Ghidra recorded at import ("/C:/Program Files/..." on Windows)."""
    p = meta.get("executable_path") or ""
    if re.match(r"^/[A-Za-z]:[/\\]", p):
        p = p[1:]
    return Path(p) if p and p != "null" else None


def md5_of(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _clock(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 3600}:{(s // 60) % 60:02d}:{s % 60:02d}"


class Pipeline:
    def __init__(self, settings: Settings, log=None):
        self.s = settings
        self.log = log or (lambda msg: print(msg, flush=True))
        self.scripts = REPO / "ghidra_scripts"

    # ------------------------------------------------------------------ headless

    def headless(self, project: str, folder: str, args: List[str], log_name: str) -> str:
        """Run analyzeHeadless on <project>/<folder>, streaming the interesting lines."""
        if not self.s.headless.exists():
            raise PipelineError(f"analyzeHeadless not found: {self.s.headless}")
        cmd = [str(self.s.headless), str(self.s.project_dir), f"{project}/{folder}"]
        cmd += args
        log_dir = self.s.out / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{log_name}.log"
        lines: List[str] = []
        with open(log_path, "w", encoding="utf-8") as log_file:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
            )
            assert proc.stdout is not None
            for raw in proc.stdout:
                log_file.write(raw)
                log_file.flush()  # keep the log readable while Ghidra runs
                line = raw.rstrip()
                lines.append(line)
                if _SHOW.search(line) and not _HIDE.search(line):
                    self.log("    " + _tidy(line))
            proc.wait()
        output = "\n".join(lines)
        if "Unable to lock project" in output:
            raise PipelineError("The Ghidra project is open in the GUI. Close it and try again.")
        if proc.returncode != 0:
            raise PipelineError(f"analyzeHeadless failed ({proc.returncode}); see {log_path}")
        return output

    def export(self, build: BuildRef) -> None:
        self.log(f"Exporting {build.project}:{build.path} as {build.label} (about a minute)...")
        t0 = time.time()
        self.headless(
            build.project,
            build.folder,
            [
                "-process", build.program, "-readOnly", "-noanalysis",
                "-scriptPath", str(self.scripts),
                "-postScript", "ExportMatchData.java", str(self.s.exports), build.label,
            ],
            f"export_{build.label}",
        )  # fmt: skip
        if not (self.s.exports / f"{build.label}.functions.csv").exists():
            raise PipelineError(f"Export of {build.path} failed; see {self.s.out / 'logs'}")
        self.log(f"  done in {_clock(time.time() - t0)}")

    def import_and_analyze(self, exe: Path, target: BuildRef, source: BuildRef) -> None:
        self.log(
            f"Importing {exe} into {target.project}:/{target.folder}/ and analysing it like "
            f"{source.path}."
        )
        self.log("  Analysing a large program can take an hour or more; progress follows.")
        t0 = time.time()
        output = self.headless(
            target.project,
            target.folder,
            [
                "-import", str(exe), "-noanalysis",
                "-scriptPath", str(self.scripts),
                "-postScript", "AnalyzeWithProgress.java", source.path,
                "-postScript", "ExportMatchData.java", str(self.s.exports), target.label,
            ],
            f"import_{target.label}",
        )  # fmt: skip
        if "conflicting" in output.lower() or "Import succeeded" not in output:
            raise PipelineError(
                f"{target.path} was not imported (it may already exist; use --existing "
                f"{target.folder}). See {self.s.out / 'logs'}"
            )
        if not (self.s.exports / f"{target.label}.functions.csv").exists():
            raise PipelineError(
                f"Analysis/export of {target.path} failed; see {self.s.out / 'logs'}"
            )
        self.log(f"  imported, analysed and exported in {_clock(time.time() - t0)}")

    # ---------------------------------------------------------------------- run

    def run(
        self,
        source: str,
        new_exe: Optional[str] = None,
        new: bool = False,
        existing: Optional[str] = None,
        name: Optional[str] = None,
        force: bool = False,
    ) -> Path:
        """Run the pipeline. Builds are given as for scripts/windows/resolve.bat."""
        proj, prog = self.s.project_name, self.s.program
        src = parse_build(source, proj, prog)
        self.s.exports.mkdir(parents=True, exist_ok=True)
        steps = 3
        self.log(f"[1/{steps}] Source build {src.label}")
        self.export(src)
        src_meta = json.loads((self.s.exports / f"{src.label}.meta.json").read_text("utf-8"))

        if new:
            exe = Path(new_exe) if new_exe else executable_from_meta(src_meta)
            if exe is None:
                raise PipelineError("No executable recorded for the source; pass --new <exe>.")
            if not exe.is_file():
                raise PipelineError(f"Executable not found: {exe}")
            folder = (name or default_build_name(self.s.build_name_format)).strip("/\\")
            # the import names the program after the file; it must sit in the source's project
            tgt = BuildRef(src.project, folder.replace("\\", "/"), exe.name)
            if not force and md5_of(exe) == src_meta.get("executable_md5"):
                raise PipelineError(
                    f"{exe} is the same executable as {src.label} (identical MD5), so there is "
                    "probably no new build yet. Use --force to import it anyway."
                )
            self.log(f"[2/{steps}] New build {tgt.label}")
            self.import_and_analyze(exe, tgt, src)
        else:
            tgt = parse_build(existing or "", proj, prog)
            self.log(f"[2/{steps}] Existing build {tgt.label}")
            self.export(tgt)

        self.log(f"[3/{steps}] Pairing {src.label} -> {tgt.label}")
        t0 = time.time()
        src_build = load_build(str(self.s.exports / src.label))
        tgt_build = load_build(str(self.s.exports / tgt.label))
        result = match(src_build, tgt_build, MatchConfig())
        pairs = self.s.out / f"pairs_{src.label}_to_{tgt.label}.csv"
        unmatched = self.s.out / f"unmatched_{src.label}_to_{tgt.label}.csv"
        n = write_pairs(result, pairs)
        u = write_unmatched(result, unmatched)
        f = result.stats()["function"]
        self.log(f"  done in {_clock(time.time() - t0)}")
        self.log("")
        self.log(
            f"Functions paired: {f['matched']:,} of {f['source_total']:,}; with your markup: "
            f"{f['source_with_user_markup_matched']:,} of {f['source_with_user_markup']:,}"
        )
        self.log(f"Pairing table ({n:,} items with your markup): {pairs}")
        self.log(f"Unmatched items with your markup ({u:,}): {unmatched}")
        self.log("")
        if src.project != tgt.project:
            self.log("Source and target are in different Ghidra projects; apply needs both in one.")
        else:
            a, b = src.spec(proj, prog), tgt.spec(proj, prog)
            self.log("Next: review the table, then apply (dry run first):")
            self.log(f"  scripts\\windows\\apply.bat {a} {b}")
            self.log(f"  scripts\\windows\\apply.bat {a} {b} apply")
        return pairs


def _tidy(line: str) -> str:
    line = re.sub(r"^\s*INFO\s+", "", line)
    line = re.sub(r"^(AnalyzeWithProgress|ExportMatchData)\.java> ", "", line)
    return re.sub(r"\s*\((GhidraScript|HeadlessAnalyzer)\)\s*$", "", line)


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def add_parser(sub) -> None:
    up = sub.add_parser(
        "update",
        help="export a source build, import/analyse or reuse a target build, export it, pair",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    up.add_argument(
        "source",
        nargs="?",
        help="build with your markup: project folder, folder/program or Project/folder/program",
    )
    mode = up.add_mutually_exclusive_group()
    mode.add_argument(
        "--new",
        nargs="?",
        const="",
        metavar="EXE",
        help="import a new build; EXE defaults to the executable the source was imported from",
    )
    mode.add_argument(
        "--existing", metavar="BUILD", help="use a build already in the project (same forms)"
    )
    up.add_argument("--name", help="project folder for --new (default: BUILD_NAME_FORMAT)")
    up.add_argument("--force", action="store_true", help="import even if the exe is unchanged")
    up.add_argument("--ghidra", help="Ghidra install folder (GHIDRA_INSTALL_DIR)")
    up.add_argument("--project-dir", help="folder containing the .gpr (GHIDRA_PROJECT_DIR)")
    up.add_argument("--project-name", help="Ghidra project name (GHIDRA_PROJECT_NAME)")
    up.add_argument("--program", help="program name in each build folder (PROGRAM_NAME)")
    up.add_argument("--exports", help="export folder (EXPORT_DIR)")
    up.add_argument("--out", help="pairing tables, reports and logs (OUT_DIR)")
    up.set_defaults(func=cmd_update)


def cmd_update(args: argparse.Namespace) -> int:
    prefs = Preferences()
    args.ghidra = args.ghidra or prefs.get("GHIDRA_INSTALL_DIR")
    args.project_dir = args.project_dir or prefs.get("GHIDRA_PROJECT_DIR")
    args.project_name = args.project_name or prefs.get("GHIDRA_PROJECT_NAME")
    args.program = args.program or prefs.get("PROGRAM_NAME")
    exports = Path(args.exports) if args.exports else prefs.path_value("EXPORT_DIR")
    out = Path(args.out) if args.out else prefs.path_value("OUT_DIR")
    name_format = prefs.get("BUILD_NAME_FORMAT") or "{year}-{month:02d}-{day:02d}"

    interactive = sys.stdin.isatty()
    if not args.source and interactive:
        args.source = _ask("Source build (project folder, or Project/folder/program): ")
    if args.new is None and not args.existing and interactive:
        choice = _ask("Target: [n]ew build from an exe, or [e]xisting folder? ").lower()
        if choice.startswith("e"):
            args.existing = _ask("Existing build (project folder, or Project/folder/program): ")
        else:
            args.new = _ask("Executable (Enter = same path as the source build): ")
            default = default_build_name(name_format)
            args.name = _ask(f"New folder name (Enter = {default}): ") or None
    missing = [
        n
        for n, v in (
            ("source", args.source),
            ("--new or --existing", args.new is not None or args.existing),
            ("--ghidra / GHIDRA_INSTALL_DIR", args.ghidra),
            ("--project-dir / GHIDRA_PROJECT_DIR", args.project_dir),
        )
        if not v
    ]
    if missing:
        print("missing: " + ", ".join(missing), file=sys.stderr)
        print(f"(preferences file: {prefs.path})", file=sys.stderr)
        return 2
    settings = Settings(
        ghidra=Path(args.ghidra),
        project_dir=Path(args.project_dir),
        project_name=args.project_name,
        program=args.program,
        exports=exports,
        out=out,
        build_name_format=name_format,
    )
    t0 = time.time()
    try:
        Pipeline(settings).run(
            args.source,
            new_exe=args.new or None,
            new=args.new is not None,
            existing=args.existing,
            name=args.name,
            force=args.force,
        )
    except PipelineError as e:
        print(f"\nerror: {e}", file=sys.stderr)
        return 1
    print(f"\nTotal time {_clock(time.time() - t0)}")
    return 0
