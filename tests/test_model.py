import json

import pytest

from ghidra_matching.model import load_build, resolve_prefix

from .helpers import build, data, fn, write_export


def test_roundtrip_preserves_awkward_strings(tmp_path):
    tricky = 'quote " comma , newline \n tab \t unicode é nul \x00'
    src = build(
        "v1",
        [
            fn(
                "00401000",
                "Foo::bar",
                namespace="Foo",
                string_refs=[tricky],
                callees=["00402000", "EXT:CreateFileW"],
                vtable_slots=[("00500000", 2)],
                data_refs=["00600000"],
            ),
            fn("00402000"),
        ],
        [data("00600000", kind="string", value=tricky, referenced_by=["00401000"])],
    )
    prefix = write_export(src, tmp_path)
    loaded = load_build(prefix)

    f = loaded.functions["00401000"]
    assert f.string_refs == [tricky]
    assert f.vtable_slots == [("00500000", 2)]
    assert f.internal_callees == ["00402000"]
    assert f.full_name == "Foo::Foo::bar"
    assert not f.is_default_name
    assert loaded.functions["00402000"].is_default_name
    assert loaded.data["00600000"].value == tricky
    assert loaded.callers["00402000"] == ["00401000"]


def test_resolve_prefix_accepts_file_paths():
    a = resolve_prefix("exports/x/v1")
    assert resolve_prefix("exports/x/v1.functions.csv") == a
    assert resolve_prefix("exports/x/v1.data.csv") == a


def test_rejects_other_format_version(tmp_path):
    prefix = write_export(build("v1", [fn("1000")]), tmp_path)
    (tmp_path / "v1.meta.json").write_text(json.dumps({"format_version": 99}))
    with pytest.raises(ValueError, match="format 99"):
        load_build(prefix)


def test_missing_column_is_reported(tmp_path):
    (tmp_path / "bad.functions.csv").write_text("address,name\n1000,x\n")
    with pytest.raises(ValueError, match="missing columns"):
        load_build(str(tmp_path / "bad"))


def test_reads_format_1_exports(tmp_path):
    prefix = write_export(build("v1", [fn("1000", "main"), fn("2000")]), tmp_path)
    for name in ("v1.functions.csv", "v1.data.csv"):
        path = tmp_path / name
        rows = path.read_text().splitlines()
        # drop the two columns added in format 2
        path.write_text("\n".join(",".join(r.split(",")[:-2]) for r in rows) + "\n")
    (tmp_path / "v1.meta.json").write_text(json.dumps({"format_version": 1}))
    b = load_build(prefix)
    assert b.format_version == 1
    assert b.functions["1000"].user_named
    assert not b.functions["2000"].user_named
