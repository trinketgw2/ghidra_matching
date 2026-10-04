"""Data model and CSV loading for the per-build exports written by ExportMatchData.java.

The column layout is documented in docs/csv_format.md.
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

FORMAT_VERSION = 3
#: Older formats that can still be read. Version 1 lacks name/signature sources, so every
#: non-default name counts as user markup there. Version 2 lacks code entries (defined=0).
SUPPORTED_FORMAT_VERSIONS = (1, 2, 3)

#: Ghidra SourceType names, lowest to highest priority.
DEFAULT = "DEFAULT"
ANALYSIS = "ANALYSIS"
AI = "AI"
IMPORTED = "IMPORTED"
USER_DEFINED = "USER_DEFINED"

FUNCTION_COLUMNS = [
    "address",
    "name",
    "namespace",
    "is_default_name",
    "is_thunk",
    "size",
    "insn_count",
    "mnemonic_hash",
    "vtable_slots",
    "string_refs",
    "callees",
    "data_refs",
    "name_source",
    "signature_source",
    "defined",
    "head_size",
    "head_hash",
    "string_args",
]

DATA_COLUMNS = [
    "address",
    "name",
    "namespace",
    "is_default_name",
    "kind",
    "datatype",
    "size",
    "value",
    "slots",
    "referenced_by",
    "name_source",
    "custom_type",
]

EXTERNAL_PREFIX = "EXT:"

# JSON list cells can be large for big functions.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


@dataclass
class Function:
    address: str
    name: str
    namespace: str = ""
    is_default_name: bool = True
    is_thunk: bool = False
    size: int = 0
    insn_count: int = 0
    mnemonic_hash: str = ""
    vtable_slots: List[Tuple[str, int]] = field(default_factory=list)
    string_refs: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    data_refs: List[str] = field(default_factory=list)
    name_source: str = ""
    signature_source: str = ""
    #: False for code that a table points to but Ghidra has no function for (size, hash and
    #: references then cover the instructions up to the first return or jump).
    defined: bool = True
    #: Size and mnemonic hash of the code up to the first return or jump (comparable between
    #: functions and code entries; empty in older exports).
    head_size: int = 0
    head_hash: str = ""
    #: (string, small constant) passed to the same call, e.g. (source file path, line).
    string_args: List[Tuple[str, int]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name_source:
            self.name_source = DEFAULT if self.is_default_name else USER_DEFINED

    @property
    def full_name(self) -> str:
        return f"{self.namespace}::{self.name}" if self.namespace else self.name

    @property
    def user_named(self) -> bool:
        return self.name_source == USER_DEFINED

    @property
    def has_user_markup(self) -> bool:
        """Name or signature set by a user (not by analysis, imports or debug info)."""
        return self.user_named or self.signature_source == USER_DEFINED

    @property
    def internal_callees(self) -> List[str]:
        """Callees inside the program (external imports are excluded)."""
        return [c for c in self.callees if not c.startswith(EXTERNAL_PREFIX)]


@dataclass
class DataItem:
    address: str
    name: str = ""
    namespace: str = ""
    is_default_name: bool = True
    kind: str = "data"  # "vtable" | "string" | "data"
    datatype: str = ""
    size: int = 0
    value: Optional[str] = None
    slots: List[str] = field(default_factory=list)
    referenced_by: List[str] = field(default_factory=list)
    name_source: str = ""
    #: Data type is a structure/union/enum/typedef/function definition (or array/pointer of one).
    custom_type: bool = False

    def __post_init__(self) -> None:
        if not self.name_source:
            self.name_source = DEFAULT if self.is_default_name else USER_DEFINED

    @property
    def full_name(self) -> str:
        return f"{self.namespace}::{self.name}" if self.namespace else self.name

    @property
    def user_named(self) -> bool:
        return self.name_source == USER_DEFINED


@dataclass
class Build:
    """All exported information about one build (one Ghidra program)."""

    label: str
    functions: Dict[str, Function] = field(default_factory=dict)
    data: Dict[str, DataItem] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)
    format_version: int = FORMAT_VERSION
    callers: Dict[str, List[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.reindex()

    def reindex(self) -> None:
        """Recompute derived indexes (callers). Call after mutating ``functions``."""
        callers: Dict[str, List[str]] = {a: [] for a in self.functions}
        for f in self.functions.values():
            for c in f.internal_callees:
                if c in callers and f.address not in callers[c]:
                    callers[c].append(f.address)
        self.callers = callers


def _bool(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes")


def _int(v: str) -> int:
    v = v.strip()
    return int(v) if v else 0


def _json_list(v: str) -> list:
    v = v.strip()
    return json.loads(v) if v else []


#: Columns added after format version 1; absent from older files.
_OPTIONAL_COLUMNS = {
    "name_source",
    "signature_source",
    "custom_type",
    "defined",
    "head_size",
    "head_hash",
    "string_args",
}


def _check_columns(path: Path, header: Optional[List[str]], expected: List[str]) -> None:
    missing = [c for c in expected if c not in (header or []) and c not in _OPTIONAL_COLUMNS]
    if missing:
        raise ValueError(f"{path}: missing columns {missing}")


def load_functions(path: Path) -> Dict[str, Function]:
    out: Dict[str, Function] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        _check_columns(path, reader.fieldnames, FUNCTION_COLUMNS)
        for row in reader:
            f = Function(
                address=row["address"],
                name=row["name"],
                namespace=row["namespace"],
                is_default_name=_bool(row["is_default_name"]),
                is_thunk=_bool(row["is_thunk"]),
                size=_int(row["size"]),
                insn_count=_int(row["insn_count"]),
                mnemonic_hash=row["mnemonic_hash"],
                vtable_slots=[(str(a), int(i)) for a, i in _json_list(row["vtable_slots"])],
                string_refs=[str(s) for s in _json_list(row["string_refs"])],
                callees=[str(c) for c in _json_list(row["callees"])],
                data_refs=[str(d) for d in _json_list(row["data_refs"])],
                name_source=row.get("name_source") or "",
                signature_source=row.get("signature_source") or "",
                defined=_bool(row.get("defined") or "1"),
                head_size=_int(row.get("head_size") or ""),
                head_hash=row.get("head_hash") or "",
                string_args=[(str(a), int(n)) for a, n in _json_list(row.get("string_args") or "")],
            )
            out[f.address] = f
    return out


def load_data(path: Path) -> Dict[str, DataItem]:
    out: Dict[str, DataItem] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        _check_columns(path, reader.fieldnames, DATA_COLUMNS)
        for row in reader:
            raw_value = row["value"].strip()
            d = DataItem(
                address=row["address"],
                name=row["name"],
                namespace=row["namespace"],
                is_default_name=_bool(row["is_default_name"]),
                kind=row["kind"] or "data",
                datatype=row["datatype"],
                size=_int(row["size"]),
                value=json.loads(raw_value) if raw_value else None,
                slots=[str(s) for s in _json_list(row["slots"])],
                referenced_by=[str(s) for s in _json_list(row["referenced_by"])],
                name_source=row.get("name_source") or "",
                custom_type=_bool(row.get("custom_type") or "0"),
            )
            out[d.address] = d
    return out


def resolve_prefix(prefix: str) -> Tuple[Path, Path, Path]:
    """Map an export prefix (``exports/game/v1.0``) to its three files.

    A path to one of the files (``.../v1.0.functions.csv``) is accepted too.
    """
    p = str(prefix)
    for suffix in (".functions.csv", ".data.csv", ".meta.json"):
        if p.endswith(suffix):
            p = p[: -len(suffix)]
            break
    return Path(p + ".functions.csv"), Path(p + ".data.csv"), Path(p + ".meta.json")


def load_build(prefix: str) -> Build:
    functions_csv, data_csv, meta_json = resolve_prefix(prefix)
    if not functions_csv.is_file():
        raise FileNotFoundError(f"{functions_csv} not found")
    meta = json.loads(meta_json.read_text(encoding="utf-8")) if meta_json.is_file() else {}
    version = int(meta.get("format_version", FORMAT_VERSION))
    if version not in SUPPORTED_FORMAT_VERSIONS:
        raise ValueError(
            f"{meta_json}: export format {version}, this tool reads formats "
            f"{', '.join(map(str, SUPPORTED_FORMAT_VERSIONS))}"
        )
    data = load_data(data_csv) if data_csv.is_file() else {}
    label = meta.get("label") or functions_csv.name[: -len(".functions.csv")]
    return Build(
        label=label,
        functions=load_functions(functions_csv),
        data=data,
        meta=meta,
        format_version=version,
    )
