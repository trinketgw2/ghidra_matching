"""Contenders: likely partners for marked-up items that were not paired, or paired weakly.

The matcher only accepts unambiguous pairs. For review, this module lists for each such
source function up to N target functions that could be its partner, with a score from 0 to
1 and the reasons behind it. Candidates come from the matcher's rejected (ambiguous)
candidates and from a search over identical code, shared strings and call arguments,
paired callers/callees and the position between paired neighbours.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .markup import source_has_markup
from .matcher import FUNCTION, MatchResult, _address_order
from .model import Build, Function

#: rank 0 is the current pair (if any), scored like the contenders for comparison
CONTENDER_COLUMNS = [
    "source_address",
    "source_name",
    "status",
    "paired_target",
    "paired_confidence",
    "rank",
    "contender_address",
    "contender_name",
    "score",
    "reasons",
    "contender_paired_with",
]

#: Strings referenced by more functions than this are too common to suggest anything.
MAX_STRING_OWNERS = 20
#: Largest run between paired neighbours searched for position-based contenders.
MAX_POSITION_GAP = 64
#: Contenders this many functions away from the expected position get no position score.
POSITION_SPREAD = 32


@dataclass
class Contender:
    target: str
    score: float
    reasons: List[str] = field(default_factory=list)
    paired_with: Optional[str] = None


class _Index:
    def __init__(self, build: Build, min_len: int):
        self.by_hash: Dict[str, List[str]] = defaultdict(list)
        self.by_head: Dict[str, List[str]] = defaultdict(list)
        self.by_string: Dict[str, List[str]] = defaultdict(list)
        self.by_arg: Dict[Tuple[str, int], List[str]] = defaultdict(list)
        for a, f in build.functions.items():
            if f.mnemonic_hash and f.defined:
                self.by_hash[f.mnemonic_hash].append(a)
            if f.head_hash:
                self.by_head[f.head_hash].append(a)
            for s in set(f.string_refs):
                if len(s) >= min_len:
                    self.by_string[s].append(a)
            for x in set(f.string_args):
                self.by_arg[x].append(a)
        self.order = _address_order(build.functions)
        self.index = {a: i for i, a in enumerate(self.order)}


def _jaccard(a: Iterable, b: Iterable) -> float:
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


class ContenderFinder:
    def __init__(self, result: MatchResult, min_string_length: int = 4):
        self.r = result
        self.src, self.tgt = result.source, result.target
        self.min_len = min_string_length
        self.fmap = {p.source: p.target for p in result.pairs if p.kind == FUNCTION}
        self.frev = {t: s for s, t in self.fmap.items()}
        self.tix = _Index(self.tgt, min_string_length)
        self.src_order = _address_order(self.src.functions)
        self.src_index = {a: i for i, a in enumerate(self.src_order)}

    # -------------------------------------------------------------- candidates

    def _position_window(self, s: str) -> List[str]:
        """Target functions between the targets of the nearest paired neighbours of s."""
        i = self.src_index[s]
        prev_t = next_t = None
        for j in range(i - 1, max(-1, i - 1 - MAX_POSITION_GAP), -1):
            t = self.fmap.get(self.src_order[j])
            if t in self.tix.index:
                prev_t = self.tix.index[t]
                break
        for j in range(i + 1, min(len(self.src_order), i + 1 + MAX_POSITION_GAP)):
            t = self.fmap.get(self.src_order[j])
            if t in self.tix.index:
                next_t = self.tix.index[t]
                break
        if prev_t is None or next_t is None or not 0 < next_t - prev_t <= MAX_POSITION_GAP:
            return []
        return self.tix.order[prev_t + 1 : next_t]

    def _expected_index(self, s: str) -> Optional[float]:
        """Where s should sit in the target's address order, from its paired neighbours."""
        i = self.src_index[s]
        before = after = None
        for j in range(i - 1, max(-1, i - 1 - 4 * MAX_POSITION_GAP), -1):
            t = self.fmap.get(self.src_order[j])
            if t in self.tix.index:
                before = (j, self.tix.index[t])
                break
        for j in range(i + 1, min(len(self.src_order), i + 1 + 4 * MAX_POSITION_GAP)):
            t = self.fmap.get(self.src_order[j])
            if t in self.tix.index:
                after = (j, self.tix.index[t])
                break
        if before and after and after[0] != before[0]:
            (j1, t1), (j2, t2) = before, after
            return t1 + (i - j1) * (t2 - t1) / (j2 - j1)
        if before:
            return before[1] + (i - before[0])
        if after:
            return after[1] - (after[0] - i)
        return None

    def _candidates(self, f: Function) -> Set[str]:
        c: Set[str] = set(self.r.rejected.get((FUNCTION, f.address), {}))
        if f.mnemonic_hash and f.defined:
            c.update(self.tix.by_hash.get(f.mnemonic_hash, [])[:50])
        if f.head_hash:
            c.update(self.tix.by_head.get(f.head_hash, [])[:50])
        for s in set(f.string_refs):
            owners = self.tix.by_string.get(s, [])
            if len(s) >= self.min_len and len(owners) <= MAX_STRING_OWNERS:
                c.update(owners)
        for x in set(f.string_args):
            owners = self.tix.by_arg.get(x, [])
            if len(owners) <= MAX_STRING_OWNERS:
                c.update(owners)
        for caller in self.src.callers.get(f.address, []):
            t = self.fmap.get(caller)
            if t in self.tgt.functions:
                c.update(self.tgt.functions[t].internal_callees)
        for callee in f.internal_callees:
            t = self.fmap.get(callee)
            if t:
                c.update(self.tgt.callers.get(t, []))
        c.update(self._position_window(f.address))
        expected = self._expected_index(f.address)
        if expected is not None:
            lo = max(0, int(expected) - 4)
            c.update(self.tix.order[lo : int(expected) + 5])
        return {t for t in c if t in self.tgt.functions}

    # ------------------------------------------------------------------ score

    def score(self, f: Function, t: str) -> Contender:
        g = self.tgt.functions[t]
        reasons: List[str] = []
        score = 0.0
        if f.defined and g.defined and f.mnemonic_hash and f.mnemonic_hash == g.mnemonic_hash:
            score += 0.35
            reasons.append("identical code")
        elif f.head_hash and f.head_hash == g.head_hash:
            score += 0.15
            reasons.append("identical start of code")
        if f.size and g.size and f.defined and g.defined:
            ratio = min(f.size, g.size) / max(f.size, g.size)
            score += 0.1 * ratio
            if ratio < 1:
                reasons.append(f"size {f.size}/{g.size}")
        js = _jaccard(
            (s for s in f.string_refs if len(s) >= self.min_len),
            (s for s in g.string_refs if len(s) >= self.min_len),
        )
        if js:
            score += 0.2 * js
            reasons.append(f"strings {js:.0%} shared")
        ja = _jaccard(f.string_args, g.string_args)
        if ja:
            score += 0.15 * ja
            reasons.append(f"call arguments {ja:.0%} shared")
        callees = [c for c in f.internal_callees if c in self.fmap]
        if callees:
            hit = sum(self.fmap[c] in set(g.internal_callees) for c in callees) / len(callees)
            if hit:
                score += 0.1 * hit
                reasons.append(f"paired callees {hit:.0%}")
        callers = [c for c in self.src.callers.get(f.address, []) if c in self.fmap]
        if callers:
            tcallers = set(self.tgt.callers.get(t, []))
            hit = sum(self.fmap[c] in tcallers for c in callers) / len(callers)
            if hit:
                score += 0.1 * hit
                reasons.append(f"paired callers {hit:.0%}")
        expected = self._expected_index(f.address)
        if expected is not None and t in self.tix.index:
            distance = abs(self.tix.index[t] - expected)
            closeness = max(0.0, 1 - distance / POSITION_SPREAD)
            if closeness:
                score += 0.15 * closeness
                reasons.append(
                    "at the expected position"
                    if distance < 1
                    else f"{distance:.0f} functions from the expected position"
                )
        rej = self.r.rejected.get((FUNCTION, f.address), {}).get(t)
        if rej:
            score += 0.1
            reasons.append(f"ambiguous {rej[0]} candidate")
        if not g.defined:
            reasons.append("no function in target yet")
        return Contender(t, round(min(score, 1.0), 3), reasons, self.frev.get(t))

    def current(self, source: str) -> Optional[Contender]:
        """The current partner of source, scored the same way, for comparison."""
        t = self.fmap.get(source)
        return self.score(self.src.functions[source], t) if t else None

    def find(self, source: str, limit: int = 5, min_score: float = 0.15) -> List[Contender]:
        f = self.src.functions[source]
        paired = self.fmap.get(source)
        scored = [self.score(f, t) for t in self._candidates(f) if t != paired]
        scored = [c for c in scored if c.score >= min_score]
        scored.sort(key=lambda c: (-c.score, c.target))
        return scored[:limit]


def write_contenders(
    result: MatchResult,
    path: Path,
    threshold: float = 0.5,
    limit: int = 5,
    min_string_length: int = 4,
) -> int:
    """Write contenders for marked-up functions that are unmatched or paired below threshold.

    Returns the number of source functions listed.
    """
    finder = ContenderFinder(result, min_string_length)
    conf = {p.source: p.confidence for p in result.pairs if p.kind == FUNCTION}
    path.parent.mkdir(parents=True, exist_ok=True)
    listed = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(CONTENDER_COLUMNS)
        for a in _address_order(result.source.functions):
            if not source_has_markup(FUNCTION, result.source, a):
                continue
            paired = finder.fmap.get(a)
            if paired is not None and conf[a] >= threshold:
                continue
            status = "unmatched" if paired is None else "low_confidence"
            contenders = finder.find(a, limit)
            f = result.source.functions[a]
            base = [
                a,
                f.full_name,
                status,
                paired or "",
                f"{conf[a]:.4f}" if paired else "",
            ]
            cur = finder.current(a)
            if cur is not None:
                g = result.target.functions[cur.target]
                w.writerow(
                    base
                    + [
                        0,
                        cur.target,
                        g.full_name,
                        f"{cur.score:.3f}",
                        "current pair; " + "; ".join(cur.reasons),
                        "",
                    ]
                )
            if not contenders:
                w.writerow(base + ["", "", "", "", "no contenders found", ""])
            for rank, c in enumerate(contenders, 1):
                g = result.target.functions[c.target]
                w.writerow(
                    base
                    + [
                        rank,
                        c.target,
                        g.full_name,
                        f"{c.score:.3f}",
                        "; ".join(c.reasons),
                        (
                            f"{c.paired_with} {result.source.functions[c.paired_with].full_name}"
                            if c.paired_with
                            else ""
                        ),
                    ]
                )
            listed += 1
    return listed
