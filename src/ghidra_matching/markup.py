"""Which paired items carry user markup worth transferring.

Matching uses every function and data item as evidence, but only items a user worked on
are written to the pairing table and applied: names and signatures set by a user (not by
auto-analysis, imports or debug info), and labels plus data types of globals a user named.
Ghidra does not record who created a data type, so the type of an unnamed global is not
treated as user markup (loader and analyzer types would be swept in otherwise). Type
definitions themselves are copied wholesale by ApplyMatchTable.java (copy_types=local).
"""

from __future__ import annotations

from typing import List

from .model import USER_DEFINED, Build, DataItem, Function


def function_markup(f: Function) -> List[str]:
    out = []
    if f.user_named:
        out.append("name")
    if f.signature_source == USER_DEFINED:
        out.append("signature")
    return out


def data_markup(src: DataItem, tgt: DataItem) -> List[str]:
    out = []
    if src.user_named:
        out.append("label")
    if src.user_named and src.datatype and src.datatype != tgt.datatype:
        out.append("datatype")
    return out


def markup_for(kind: str, source: Build, target: Build, src_addr: str, tgt_addr: str) -> List[str]:
    if kind == "function":
        return function_markup(source.functions[src_addr])
    return data_markup(source.data[src_addr], target.data[tgt_addr])


def source_has_markup(kind: str, source: Build, addr: str) -> bool:
    """Markup that could be transferred, independent of what the target has."""
    if kind == "function":
        return source.functions[addr].has_user_markup
    return source.data[addr].user_named
