"""Builders for small synthetic exports used across the tests."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from ghidra_matching.model import DATA_COLUMNS, FUNCTION_COLUMNS, Build, DataItem, Function


def fn(address: str, name: str = "", **kw) -> Function:
    return Function(
        address=address,
        name=name or f"FUN_{address}",
        is_default_name=not name,
        size=kw.pop("size", 100),
        **kw,
    )


def data(address: str, name: str = "", **kw) -> DataItem:
    return DataItem(address=address, name=name or f"DAT_{address}", is_default_name=not name, **kw)


def build(label: str, functions: Iterable[Function], items: Iterable[DataItem] = ()) -> Build:
    return Build(
        label=label,
        functions={f.address: f for f in functions},
        data={d.address: d for d in items},
    )


def write_export(b: Build, directory: Path) -> str:
    """Write ``b`` in the ExportMatchData.java format; returns the export prefix."""
    prefix = directory / b.label
    with open(f"{prefix}.functions.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(FUNCTION_COLUMNS)
        for f in b.functions.values():
            w.writerow(
                [
                    f.address,
                    f.name,
                    f.namespace,
                    int(f.is_default_name),
                    int(f.is_thunk),
                    f.size,
                    f.insn_count,
                    f.mnemonic_hash,
                    json.dumps([list(s) for s in f.vtable_slots]),
                    json.dumps(f.string_refs),
                    json.dumps(f.callees),
                    json.dumps(f.data_refs),
                    f.name_source,
                    f.signature_source,
                    int(f.defined),
                    f.head_size,
                    f.head_hash,
                    json.dumps([list(x) for x in f.string_args]),
                ]
            )
    with open(f"{prefix}.data.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(DATA_COLUMNS)
        for d in b.data.values():
            w.writerow(
                [
                    d.address,
                    d.name,
                    d.namespace,
                    int(d.is_default_name),
                    d.kind,
                    d.datatype,
                    d.size,
                    json.dumps(d.value) if d.value is not None else "",
                    json.dumps(d.slots),
                    json.dumps(d.referenced_by),
                    d.name_source,
                    int(d.custom_type),
                ]
            )
    Path(f"{prefix}.meta.json").write_text(
        json.dumps({"format_version": 3, "label": b.label}), encoding="utf-8"
    )
    return str(prefix)
