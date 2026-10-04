"""Evaluate a pairing table against name-based ground truth.

When both builds carry the same symbols (debug builds, or two builds that were
both marked up by hand), identical unique names give the correct pairing. Run
the matcher with names disabled (``ghidra-match pair --blind``) and compare its
output against that truth to measure precision and recall.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from .matcher import DATA, FUNCTION, Pair
from .model import Build


def name_truth(source: Build, target: Build, kind: str) -> Dict[str, str]:
    """source address -> target address for names that are unique and non-default on both sides."""
    src_items = source.functions if kind == FUNCTION else source.data
    tgt_items = target.functions if kind == FUNCTION else target.data

    def unique(items: dict) -> Dict[str, str]:
        seen: Dict[str, List[str]] = defaultdict(list)
        for addr, it in items.items():
            if not it.is_default_name:
                seen[it.full_name].append(addr)
        return {n: a[0] for n, a in seen.items() if len(a) == 1}

    us, ut = unique(src_items), unique(tgt_items)
    return {us[n]: ut[n] for n in us.keys() & ut.keys()}


@dataclass
class KindScore:
    truth: int = 0
    predicted_in_truth: int = 0
    correct: int = 0
    wrong: List[Tuple[str, str, str]] = field(default_factory=list)  # (source, predicted, expected)

    @property
    def precision(self) -> float:
        return self.correct / self.predicted_in_truth if self.predicted_in_truth else 0.0

    @property
    def recall(self) -> float:
        return self.correct / self.truth if self.truth else 0.0


def evaluate(source: Build, target: Build, pairs: Sequence[Pair]) -> Dict[str, KindScore]:
    scores: Dict[str, KindScore] = {}
    for kind in (FUNCTION, DATA):
        truth = name_truth(source, target, kind)
        score = KindScore(truth=len(truth))
        for p in pairs:
            if p.kind != kind or p.source not in truth:
                continue
            score.predicted_in_truth += 1
            if truth[p.source] == p.target:
                score.correct += 1
            else:
                score.wrong.append((p.source, p.target, truth[p.source]))
        scores[kind] = score
    return scores
