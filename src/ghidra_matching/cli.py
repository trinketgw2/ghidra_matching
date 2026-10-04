"""Command line interface: ``ghidra-match {info,pair,eval}``."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional

from . import __version__
from .evaluate import evaluate
from .matcher import MatchConfig, match
from .model import FORMAT_VERSION, load_build
from .pairing import read_pairs, write_pairs, write_unmatched
from .pipeline import add_parser as add_update_parser


def cmd_info(args: argparse.Namespace) -> int:
    for prefix in args.exports:
        b = load_build(prefix)
        funcs = b.functions.values()
        kinds = Counter(d.kind for d in b.data.values())
        info = {
            "label": b.label,
            "program": b.meta.get("program_name"),
            "functions": len(b.functions),
            "functions_named": sum(1 for f in funcs if not f.is_default_name),
            "functions_user_named": sum(1 for f in funcs if f.user_named),
            "functions_user_signature": sum(
                1 for f in funcs if f.signature_source == "USER_DEFINED"
            ),
            "functions_with_strings": sum(1 for f in funcs if f.string_refs),
            "functions_in_vtables": sum(1 for f in funcs if f.vtable_slots),
            "thunks": sum(1 for f in funcs if f.is_thunk),
            "data": len(b.data),
            "data_by_kind": dict(kinds),
            "data_named": sum(1 for d in b.data.values() if not d.is_default_name),
            "data_user_named": sum(1 for d in b.data.values() if d.user_named),
            "data_custom_type": sum(1 for d in b.data.values() if d.custom_type),
        }
        print(json.dumps(info, indent=2))
    return 0


def cmd_pair(args: argparse.Namespace) -> int:
    source = load_build(args.source)
    target = load_build(args.target)
    config = MatchConfig(
        min_string_length=args.min_string_length,
        min_body_insns=args.min_body_insns,
        size_ratio=args.size_ratio,
        use_names=not args.blind,
        propagate=not args.no_propagate,
        use_neighbors=not args.no_neighbors,
    )
    result = match(source, target, config)
    n = write_pairs(result, Path(args.output), args.min_confidence, markup_only=not args.all)
    what = "pairs" if args.all else "pairs with user markup"
    print(f"wrote {n} {what} to {args.output}", file=sys.stderr)
    for b in (source, target):
        if b.format_version < FORMAT_VERSION:
            print(
                f"warning: {b.label} is export format {b.format_version}, which does not record "
                "who set names; every non-default name counts as user markup. Re-export with "
                "the current ExportMatchData.java.",
                file=sys.stderr,
            )
    if args.unmatched:
        u = write_unmatched(result, Path(args.unmatched))
        print(
            f"wrote {u} unmatched source items with user markup to {args.unmatched}",
            file=sys.stderr,
        )
    print(json.dumps(result.stats(), indent=2))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    source = load_build(args.source)
    target = load_build(args.target)
    pairs = read_pairs(Path(args.pairs))
    scores = evaluate(source, target, pairs)
    report = {
        kind: {
            "truth_pairs": s.truth,
            "predicted_in_truth": s.predicted_in_truth,
            "correct": s.correct,
            "precision": round(s.precision, 4),
            "recall": round(s.recall, 4),
        }
        for kind, s in scores.items()
    }
    print(json.dumps(report, indent=2))
    if args.show_wrong:
        for kind, s in scores.items():
            items_s = source.functions if kind == "function" else source.data
            items_t = target.functions if kind == "function" else target.data
            for src, got, want in s.wrong[: args.show_wrong]:
                print(
                    f"WRONG {kind} {src} {items_s[src].full_name}: "
                    f"got {got} ({items_t[got].full_name if got in items_t else '?'}), "
                    f"expected {want}",
                    file=sys.stderr,
                )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghidra-match",
        description="Pair functions and data between two Ghidra exports of different builds.",
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="summarise one or more exports")
    info.add_argument("exports", nargs="+", help="export prefix, e.g. exports/game/v1.0")
    info.set_defaults(func=cmd_info)

    pair = sub.add_parser("pair", help="create a pairing table from two exports")
    pair.add_argument("source", help="export prefix of the build that has the markup")
    pair.add_argument("target", help="export prefix of the build to receive the markup")
    pair.add_argument("-o", "--output", required=True, help="pairing table CSV to write")
    pair.add_argument(
        "--unmatched", help="also write source items with user markup that found no pair"
    )
    pair.add_argument(
        "--all",
        action="store_true",
        help="write every pair, not only those carrying user markup (needed for eval)",
    )
    pair.add_argument("--min-confidence", type=float, default=0.0)
    pair.add_argument("--min-string-length", type=int, default=MatchConfig.min_string_length)
    pair.add_argument("--min-body-insns", type=int, default=MatchConfig.min_body_insns)
    pair.add_argument("--size-ratio", type=float, default=MatchConfig.size_ratio)
    pair.add_argument(
        "--blind", action="store_true", help="do not use names as evidence (for evaluation)"
    )
    pair.add_argument("--no-propagate", action="store_true", help="anchors only")
    pair.add_argument(
        "--no-neighbors",
        action="store_true",
        help="do not pair functions by position between matched neighbours",
    )
    pair.set_defaults(func=cmd_pair)

    ev = sub.add_parser("eval", help="score a pairing table against name-based ground truth")
    ev.add_argument("source")
    ev.add_argument("target")
    ev.add_argument("pairs")
    ev.add_argument("--show-wrong", type=int, default=0, metavar="N", help="print N wrong pairs")
    ev.set_defaults(func=cmd_eval)

    add_update_parser(sub)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
