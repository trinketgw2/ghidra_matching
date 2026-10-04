import csv
import json

from ghidra_matching.cli import main

from .helpers import build, data, fn, write_export


def test_pair_and_eval_end_to_end(tmp_path, capsys):
    src = build(
        "v1",
        [
            fn("1000", "main", callees=["2000"], string_refs=["usage: tool <file>"]),
            fn("2000", "parse_args", string_refs=["--verbose"]),
            fn("3000", "unused_in_v2"),
        ],
    )
    tgt = build(
        "v2",
        [
            fn("1100", "main", callees=["2100"], string_refs=["usage: tool <file>"]),
            fn("2100", "parse_args", string_refs=["--verbose"]),
        ],
    )
    s = write_export(src, tmp_path)
    t = write_export(tgt, tmp_path)
    out = tmp_path / "pairs" / "v1_to_v2.csv"
    unmatched = tmp_path / "unmatched.csv"

    args = ["pair", s, t, "-o", str(out), "--blind", "--all", "--unmatched", str(unmatched)]
    assert main(args) == 0
    with open(out, newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {(r["source_address"], r["target_address"]) for r in rows} == {
        ("1000", "1100"),
        ("2000", "2100"),
    }
    assert rows[0]["source_name"] in ("main", "parse_args")
    with open(unmatched, newline="") as fh:
        assert [r["source_name"] for r in csv.DictReader(fh)] == ["unused_in_v2"]
    capsys.readouterr()

    assert main(["eval", s, t, str(out)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["function"]["precision"] == 1.0
    assert report["function"]["recall"] == 1.0


def test_info(tmp_path, capsys):
    prefix = write_export(build("v1", [fn("1000", "main"), fn("2000")]), tmp_path)
    assert main(["info", prefix]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["functions"] == 2
    assert info["functions_named"] == 1


def test_pair_table_keeps_only_user_markup(tmp_path):
    src = build(
        "v1",
        [
            fn("1000", "main", name_source="IMPORTED", callees=["2000", "3000", "4000"]),
            fn("2000", "Player::Update"),  # user named
            fn("3000", "caseD_4", name_source="ANALYSIS"),
            fn("4000", signature_source="USER_DEFINED"),  # default name, user signature
        ],
        [
            data("g1", "g_player", referenced_by=["2000"], datatype="/MyTypes/Player"),
            # retyped but unnamed: Ghidra cannot tell user types from loader types here
            data("g2", referenced_by=["3000"], datatype="/MyTypes/Stats", custom_type=True),
            data("g3", "s_hello", name_source="ANALYSIS", kind="string", value="hello world"),
        ],
    )
    for f, d in (("2000", "g1"), ("3000", "g2")):
        src.functions[f].data_refs = [d]
    tgt = build(
        "v2",
        [
            fn("1100", "main", name_source="IMPORTED", callees=["2100", "3100", "4100"]),
            fn("2100", data_refs=["G1"]),
            fn("3100", data_refs=["G2"]),
            fn("4100"),
        ],
        [
            data("G1", referenced_by=["2100"]),
            data("G2", referenced_by=["3100"]),
            data("G3", "s_hello", name_source="ANALYSIS", kind="string", value="hello world"),
        ],
    )
    out = tmp_path / "pairs.csv"
    assert (
        main(["pair", write_export(src, tmp_path), write_export(tgt, tmp_path), "-o", str(out)])
        == 0
    )
    with open(out, newline="") as fh:
        rows = {
            (r["kind"], r["source_address"]): (r["target_address"], r["markup"])
            for r in csv.DictReader(fh)
        }
    assert rows == {
        ("function", "2000"): ("2100", "name"),
        ("function", "4000"): ("4100", "signature"),
        ("data", "g1"): ("G1", "label+datatype"),
    }

    everything = tmp_path / "all.csv"
    main(["pair", str(tmp_path / "v1"), str(tmp_path / "v2"), "-o", str(everything), "--all"])
    with open(everything, newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 7


def test_update_helpers():
    import datetime

    from ghidra_matching.pipeline import default_build_name, executable_from_meta

    day = datetime.date(2024, 5, 1)
    assert default_build_name(today=day) == "2024-05-01"
    assert default_build_name("{year}{mon}{day}", today=day) == "2024May1"
    exe = executable_from_meta({"executable_path": "/C:/Program Files/App/program.exe"})
    assert str(exe).replace("\\", "/") == "C:/Program Files/App/program.exe"
    assert executable_from_meta({"executable_path": "/home/me/sample"}).name == "sample"
    assert executable_from_meta({}) is None


def test_preferences_file(tmp_path, monkeypatch):
    from ghidra_matching.config import REPO, Preferences, parse

    text = "# comment\n\nGHIDRA_PROJECT_NAME = Demo\nAPPLY_OPTIONS=min_confidence=0.5 x=1\n"
    assert parse(text) == {
        "GHIDRA_PROJECT_NAME": "Demo",
        "APPLY_OPTIONS": "min_confidence=0.5 x=1",
    }
    cfg = tmp_path / "prefs.cfg"
    cfg.write_text("GHIDRA_PROJECT_NAME=FromFile\nEXPORT_DIR=data/exports\n")
    monkeypatch.delenv("GHIDRA_PROJECT_NAME", raising=False)
    prefs = Preferences(path=cfg)
    assert prefs.get("GHIDRA_PROJECT_NAME") == "FromFile"
    assert prefs.path_value("EXPORT_DIR") == REPO / "data" / "exports"
    assert prefs.get("OUT_DIR") == "out"  # built-in default
    monkeypatch.setenv("GHIDRA_PROJECT_NAME", "FromEnv")
    assert prefs.get("GHIDRA_PROJECT_NAME") == "FromEnv"


def test_parse_build_forms():
    import pytest

    from ghidra_matching.pipeline import PipelineError, parse_build

    b = parse_build("v1.1", "Proj", "app.exe")
    assert (b.project, b.folder, b.program, b.label) == ("Proj", "v1.1", "app.exe", "v1.1")
    assert parse_build("v1.1/other.exe", "Proj", None).program == "other.exe"
    full = parse_build("Other/builds/v1.1/app.exe", None, None)
    assert (full.project, full.folder, full.program, full.label) == (
        "Other",
        "builds/v1.1",
        "app.exe",
        "v1.1",
    )
    assert parse_build("\\\\Other\\\\v1.1\\\\app.exe", None, None).folder == "v1.1"
    assert full.spec("Other", "app.exe") == "builds/v1.1"
    assert full.spec("Proj", "app.exe") == "Other/builds/v1.1/app.exe"
    with pytest.raises(PipelineError, match="No project"):
        parse_build("v1.1", None, "app.exe")
    with pytest.raises(PipelineError, match="No program"):
        parse_build("v1.1", "Proj", None)


def test_contenders_for_ambiguous_function(tmp_path):
    # two identical unnamed copies in the target: the matcher pairs neither, the
    # contenders list both
    src = build("v1", [fn("1000", "Player::Update", mnemonic_hash="h1", insn_count=40, size=64)])
    tgt = build(
        "v2",
        [
            fn("2000", mnemonic_hash="h1", insn_count=40, size=64),
            fn("3000", mnemonic_hash="h1", insn_count=40, size=64),
            fn("4000", mnemonic_hash="zz", insn_count=40, size=500),
        ],
    )
    out = tmp_path / "contenders.csv"
    args = [
        "pair",
        write_export(src, tmp_path),
        write_export(tgt, tmp_path),
        "-o",
        str(tmp_path / "p.csv"),
        "--contenders",
        str(out),
        "--blind",
    ]
    assert main(args) == 0
    with open(out, newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["contender_address"] for r in rows} == {"2000", "3000"}
    assert all(r["status"] == "unmatched" for r in rows)
    assert "identical code" in rows[0]["reasons"]
