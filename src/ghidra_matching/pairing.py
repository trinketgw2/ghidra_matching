"""Reading and writing the pairing table consumed by ApplyMatchTable.java."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, List

from .markup import markup_for, source_has_markup
from .matcher import FUNCTION, MatchResult, Pair

PAIR_COLUMNS = [
    "kind",
    "source_address",
    "target_address",
    "source_name",
    "target_name",
    "method",
    "confidence",
    "markup",
]


def write_pairs(
    result: MatchResult, path: Path, min_confidence: float = 0.0, markup_only: bool = True
) -> int:
    """Write the pairing table.

    With ``markup_only`` (the default) only pairs whose source carries user markup are
    written; the ``markup`` column says what will be transferred.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(PAIR_COLUMNS)
        for p in result.pairs:
            if p.confidence < min_confidence:
                continue
            markup = markup_for(p.kind, result.source, result.target, p.source, p.target)
            if markup_only and not markup:
                continue
            src = result.source.functions if p.kind == FUNCTION else result.source.data
            tgt = result.target.functions if p.kind == FUNCTION else result.target.data
            w.writerow(
                [
                    p.kind,
                    p.source,
                    p.target,
                    src[p.source].full_name,
                    tgt[p.target].full_name,
                    p.method,
                    f"{p.confidence:.4f}",
                    "+".join(markup),
                ]
            )
            n += 1
    return n


def read_pairs(path: Path) -> List[Pair]:
    with open(path, newline="", encoding="utf-8") as fh:
        return [
            Pair(
                kind=row["kind"],
                source=row["source_address"],
                target=row["target_address"],
                method=row.get("method", ""),
                confidence=float(row.get("confidence") or 1.0),
            )
            for row in csv.DictReader(fh)
        ]


def write_unmatched(result: MatchResult, path: Path) -> int:
    """List source items that carry user markup but were not paired."""
    matched = {(p.kind, p.source) for p in result.pairs}
    rows: Iterable = (
        (kind, addr, item.full_name)
        for kind, items in ((FUNCTION, result.source.functions), ("data", result.source.data))
        for addr, item in items.items()
        if (kind, addr) not in matched and source_has_markup(kind, result.source, addr)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["kind", "source_address", "source_name"])
        for row in rows:
            w.writerow(row)
            n += 1
    return n
