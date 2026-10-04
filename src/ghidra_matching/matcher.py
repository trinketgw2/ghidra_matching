"""Pairs functions and data between a source build and a target build.

The matcher works in two stages:

1. **Anchors**: high-confidence, one-to-one matches from features that survive
   recompilation: identical non-default names (exports, imports, RTTI), identical
   sets of referenced strings, strings referenced by exactly one function on each
   side, identical instruction-mnemonic hashes, unique string values.
2. **Propagation**: starting from the anchors, neighbours are paired when the
   neighbourhood is unambiguous: callees/callers, vtable slots of paired vtables,
   data referenced by paired functions, functions referencing paired data.

Every accepted pair is strictly one-to-one. Within one step a candidate is only
accepted if neither side has a competing candidate, so ambiguity leads to "no
match" rather than a guess. Confidence decays along propagation chains.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .markup import markup_for, source_has_markup
from .model import IMPORTED, USER_DEFINED, Build, Function

FUNCTION = "function"
DATA = "data"

Candidates = Dict[Tuple[str, str], float]

TRUSTED_NAME_SOURCES = (IMPORTED, USER_DEFINED)


@dataclass(frozen=True)
class Pair:
    kind: str  # FUNCTION | DATA
    source: str
    target: str
    method: str
    confidence: float


@dataclass
class MatchConfig:
    #: Strings shorter than this are ignored as matching evidence.
    min_string_length: int = 4
    #: Minimum instruction count for the mnemonic-hash anchor (tiny stubs repeat a lot).
    min_body_insns: int = 10
    #: Propagated function pairs must have sizes within this factor of each other.
    size_ratio: float = 3.0
    #: Use name equality as an anchor. Disable to evaluate the other heuristics.
    use_names: bool = True
    #: Run the propagation stage.
    propagate: bool = True
    max_iterations: int = 100
    #: Pair unmatched functions by position between matched neighbours (same link order).
    use_neighbors: bool = True
    #: Largest run of unmatched functions between two matched neighbours that is paired.
    max_neighbor_gap: int = 32
    #: Neighbour pairs must have sizes within this factor of each other.
    neighbor_size_ratio: float = 2.0


# Base confidences. Propagated pairs multiply the parent pair's confidence.
CONF_NAME = 1.0
CONF_STRING_SET = 0.95
CONF_STRING_ARGS = 0.95
CONF_BODY_HASH = 0.9
CONF_STRING_VALUE = 0.9
CONF_UNIQUE_STRING = 0.8
DECAY_VTABLE_SLOT = 0.95
DECAY_CALLEE_SINGLE = 0.9
DECAY_CALLEE_POSITIONAL = 0.8
DECAY_CALLER_SINGLE = 0.85
DECAY_DATA_REF_SINGLE = 0.9
DECAY_DATA_REF_POSITIONAL = 0.8
DECAY_DATA_REFERRER = 0.8
DECAY_NEIGHBOR = 0.75
DECAY_SOURCE_ORDER = 0.85
CONF_SOURCE_ORDER = 0.8  # no paired function in the same file to lean on


@dataclass
class MatchResult:
    source: Build
    target: Build
    pairs: List[Pair] = field(default_factory=list)
    #: (kind, source) -> {target: (method, confidence)} for candidates that were rejected
    #: because the source or the target had a competing candidate in the same step.
    rejected: Dict[Tuple[str, str], Dict[str, Tuple[str, float]]] = field(default_factory=dict)

    def by_kind(self, kind: str) -> List[Pair]:
        return [p for p in self.pairs if p.kind == kind]

    def stats(self) -> dict:
        out: dict = {}
        for kind, src_items, tgt_items in (
            (FUNCTION, self.source.functions, self.target.functions),
            (DATA, self.source.data, self.target.data),
        ):
            pairs = self.by_kind(kind)
            methods = Counter(p.method for p in pairs)
            with_markup = [a for a in src_items if source_has_markup(kind, self.source, a)]
            matched_src = {p.source for p in pairs}
            transfers: Counter = Counter()
            agree = disagree = 0
            for p in pairs:
                for m in markup_for(kind, self.source, self.target, p.source, p.target):
                    transfers[m] += 1
                s, t = src_items[p.source], tgt_items[p.target]
                # analysis names often embed addresses (switchD_1400..., caseD_...), so only
                # names from users, imports or debug info are compared
                if s.name_source in TRUSTED_NAME_SOURCES and t.name_source in TRUSTED_NAME_SOURCES:
                    if s.full_name == t.full_name:
                        agree += 1
                    else:
                        disagree += 1
            out[kind] = {
                "source_total": len(src_items),
                "target_total": len(tgt_items),
                "matched": len(pairs),
                "source_with_user_markup": len(with_markup),
                "source_with_user_markup_matched": sum(1 for a in with_markup if a in matched_src),
                "markup_to_transfer": dict(sorted(transfers.items())),
                "names_agree": agree,
                "names_disagree": disagree,
                "by_method": dict(sorted(methods.items(), key=lambda kv: -kv[1])),
            }
        return out


class Matcher:
    def __init__(self, source: Build, target: Build, config: Optional[MatchConfig] = None):
        self.src = source
        self.tgt = target
        self.cfg = config or MatchConfig()
        self.fwd: Dict[str, Dict[str, str]] = {FUNCTION: {}, DATA: {}}
        self.rev: Dict[str, Dict[str, str]] = {FUNCTION: {}, DATA: {}}
        self.pairs: Dict[Tuple[str, str], Pair] = {}
        self._line_cache: Dict[int, Dict[str, Dict[str, int]]] = {}
        self.rejected: Dict[Tuple[str, str], Dict[str, Tuple[str, float]]] = {}

    # ------------------------------------------------------------------ driver

    def run(self) -> MatchResult:
        if self.cfg.use_names:
            self._anchor_names(FUNCTION, self.src.functions, self.tgt.functions)
            self._anchor_names(DATA, self.src.data, self.tgt.data)
        self._anchor_string_sets()
        # identical code beats shared (string, line) arguments: run the hash anchor first
        self._anchor_body_hash()
        self._anchor_string_args()
        self._anchor_unique_strings()
        self._anchor_string_values()

        if self.cfg.propagate:
            steps: Sequence[Callable[[], int]] = (
                self._propagate_vtables,
                self._propagate_vtable_slots,
                self._propagate_calls,
                self._propagate_data_refs,
                self._propagate_data_referrers,
                self._propagate_source_order,
            )
            # neighbour pairing is the weakest evidence: only run it once the other steps
            # have converged, then let them build on what it found
            for _ in range(self.cfg.max_iterations):
                for _ in range(self.cfg.max_iterations):
                    if sum(step() for step in steps) == 0:
                        break
                if not self.cfg.use_neighbors or self._propagate_neighbors() == 0:
                    break

        pairs = sorted(self.pairs.values(), key=lambda p: (p.kind, p.source))
        return MatchResult(self.src, self.tgt, pairs, self.rejected)

    # -------------------------------------------------------------- acceptance

    def _accept(self, kind: str, method: str, candidates: Candidates) -> int:
        """Accept candidates whose source and target have no competing candidate."""
        fwd, rev = self.fwd[kind], self.rev[kind]
        by_src: Dict[str, set] = defaultdict(set)
        by_tgt: Dict[str, set] = defaultdict(set)
        live = {k: v for k, v in candidates.items() if k[0] not in fwd and k[1] not in rev}
        for s, t in live:
            by_src[s].add(t)
            by_tgt[t].add(s)
        accepted = 0
        for (s, t), conf in sorted(live.items()):
            if len(by_src[s]) == 1 and len(by_tgt[t]) == 1:
                fwd[s] = t
                rev[t] = s
                self.pairs[(kind, s)] = Pair(kind, s, t, method, round(conf, 4))
                accepted += 1
            else:
                seen = self.rejected.setdefault((kind, s), {})
                if conf > seen.get(t, ("", 0.0))[1]:
                    seen[t] = (method, round(conf, 4))
        return accepted

    def _conf(self, kind: str, source: str) -> float:
        return self.pairs[(kind, source)].confidence

    @staticmethod
    def _add(cands: Candidates, s: str, t: str, conf: float) -> None:
        if conf > cands.get((s, t), 0.0):
            cands[(s, t)] = conf

    def _plausible(self, s: str, t: str) -> bool:
        fs, ft = self.src.functions.get(s), self.tgt.functions.get(t)
        if fs is None or ft is None:
            return False
        if fs.is_thunk != ft.is_thunk:
            return False
        if not fs.defined or not ft.defined:
            return self._heads_agree(fs, ft)
        if fs.is_thunk or fs.size == 0 or ft.size == 0:
            return True
        ratio = max(fs.size, ft.size) / min(fs.size, ft.size)
        return ratio <= self.cfg.size_ratio

    @staticmethod
    def _heads_agree(fs: Function, ft: Function) -> bool:
        """Code entries only have their first basic blocks: compare those with the other side.

        Identical heads agree. Different heads agree only if they have the same size (an
        edited instruction); anything else is a different piece of code. Without head data
        (older exports) there is nothing to compare.
        """
        if not fs.head_hash or not ft.head_hash:
            return True
        return fs.head_hash == ft.head_hash or fs.head_size == ft.head_size

    def _data_compatible(self, s: str, t: str) -> bool:
        ds, dt = self.src.data.get(s), self.tgt.data.get(t)
        return ds is not None and dt is not None and ds.kind == dt.kind

    # ----------------------------------------------------------------- anchors

    def _anchor_unique_keys(
        self,
        kind: str,
        method: str,
        conf: float,
        src_keys: Iterable[Tuple[str, object]],
        tgt_keys: Iterable[Tuple[str, object]],
    ) -> int:
        """Pair items whose key occurs exactly once on each side."""

        def unique(pairs: Iterable[Tuple[str, object]]) -> Dict[object, str]:
            seen: Dict[object, List[str]] = defaultdict(list)
            for addr, key in pairs:
                seen[key].append(addr)
            return {k: v[0] for k, v in seen.items() if len(v) == 1}

        us, ut = unique(src_keys), unique(tgt_keys)
        cands = {(us[k], ut[k]): conf for k in us.keys() & ut.keys()}
        return self._accept(kind, method, cands)

    def _anchor_names(self, kind: str, src_items: dict, tgt_items: dict) -> int:
        def keys(items: dict):
            return ((a, it.full_name) for a, it in items.items() if not it.is_default_name)

        return self._anchor_unique_keys(kind, "name", CONF_NAME, keys(src_items), keys(tgt_items))

    def _strings_of(self, f: Function) -> List[str]:
        return [s for s in f.string_refs if len(s) >= self.cfg.min_string_length]

    def _anchor_string_sets(self) -> int:
        def keys(build: Build):
            for a, f in build.functions.items():
                strings = tuple(sorted(set(self._strings_of(f))))
                if strings:
                    yield a, strings

        return self._anchor_unique_keys(
            FUNCTION, "string_set", CONF_STRING_SET, keys(self.src), keys(self.tgt)
        )

    def _anchor_string_args(self) -> int:
        """Pair functions with an identical set of (string, constant) call arguments.

        Separates functions that share assert texts and file paths but sit at different lines,
        e.g. errorContext("expr", "D:\\...\\List.h", 0x9d).
        """

        def keys(build: Build):
            for a, f in build.functions.items():
                args = tuple(
                    sorted({x for x in f.string_args if len(x[0]) >= self.cfg.min_string_length})
                )
                if args:
                    yield a, args

        return self._anchor_unique_keys(
            FUNCTION, "string_args", CONF_STRING_ARGS, keys(self.src), keys(self.tgt)
        )

    def _anchor_unique_strings(self) -> int:
        """A string referenced by exactly one function on each side votes for that pair."""

        def owners(build: Build) -> Dict[str, str]:
            refs: Dict[str, set] = defaultdict(set)
            for a, f in build.functions.items():
                for s in self._strings_of(f):
                    refs[s].add(a)
            return {s: next(iter(fs)) for s, fs in refs.items() if len(fs) == 1}

        os_, ot = owners(self.src), owners(self.tgt)
        votes: Counter = Counter()
        for s in os_.keys() & ot.keys():
            votes[(os_[s], ot[s])] += 1
        cands = {
            k: min(0.95, CONF_UNIQUE_STRING + 0.05 * (n - 1))
            for k, n in votes.items()
            if self._plausible(*k)
        }
        return self._accept(FUNCTION, "unique_string", cands)

    def _anchor_body_hash(self) -> int:
        def keys(build: Build):
            for a, f in build.functions.items():
                if f.mnemonic_hash and f.insn_count >= self.cfg.min_body_insns:
                    yield a, (f.mnemonic_hash, f.size)

        return self._anchor_unique_keys(
            FUNCTION, "body_hash", CONF_BODY_HASH, keys(self.src), keys(self.tgt)
        )

    def _anchor_string_values(self) -> int:
        def keys(build: Build):
            for a, d in build.data.items():
                if d.kind == "string" and d.value and len(d.value) >= self.cfg.min_string_length:
                    yield a, d.value

        return self._anchor_unique_keys(
            DATA, "string_value", CONF_STRING_VALUE, keys(self.src), keys(self.tgt)
        )

    # ------------------------------------------------------------- propagation

    def _propagate_vtables(self) -> int:
        """Pair vtables whose slots point at already paired functions (same slot index)."""
        fmap = self.fwd[FUNCTION]
        cands: Candidates = {}
        for va, vs in self.src.data.items():
            if vs.kind != "vtable" or va in self.fwd[DATA] or not vs.slots:
                continue
            votes: Counter = Counter()
            for i, s in enumerate(vs.slots):
                t = fmap.get(s)
                if t is None or t not in self.tgt.functions:
                    continue
                for vt_addr, j in self.tgt.functions[t].vtable_slots:
                    if i == j:
                        votes[vt_addr] += 1
            ranked = votes.most_common(2)
            if not ranked or (len(ranked) > 1 and ranked[0][1] == ranked[1][1]):
                continue
            vt_addr, n = ranked[0]
            if not self._data_compatible(va, vt_addr):
                continue
            self._add(cands, va, vt_addr, min(0.95, 0.5 + 0.45 * n / len(vs.slots)))
        return self._accept(DATA, "vtable_votes", cands)

    def _propagate_vtable_slots(self) -> int:
        """Pair functions at the same slot index of paired vtables.

        A slot is paired only where the layouts are known to line up: the nearest already
        paired slot before it and the nearest one after it (where they exist) must be paired
        with the target slot at the same index, and at least one of them must exist unless
        both tables have the same length. A slot inserted or removed in the new build thus
        stops the pairing at the point where the indices start to disagree.
        """
        fmap, frev = self.fwd[FUNCTION], self.rev[FUNCTION]
        cands: Candidates = {}
        for va, vb in self.fwd[DATA].items():
            vs, vt = self.src.data.get(va), self.tgt.data.get(vb)
            if vs is None or vt is None or vs.kind != "vtable" or vt.kind != "vtable":
                continue
            conf = self._conf(DATA, va) * DECAY_VTABLE_SLOT
            n = min(len(vs.slots), len(vt.slots))
            # per index: True = paired with the same index, False = paired elsewhere
            state = [
                (fmap[vs.slots[i]] == vt.slots[i]) if vs.slots[i] in fmap else None
                for i in range(n)
            ]
            same_length = len(vs.slots) == len(vt.slots)
            for i in range(n):
                s, t = vs.slots[i], vt.slots[i]
                if state[i] is not None or t in frev:
                    continue
                before = next(
                    (state[j] for j in range(i - 1, -1, -1) if state[j] is not None), None
                )
                after = next((state[j] for j in range(i + 1, n) if state[j] is not None), None)
                if before is False or after is False:
                    continue
                if before is None and after is None and not same_length:
                    continue
                if self._plausible(s, t):
                    self._add(cands, s, t, conf)
        return self._accept(FUNCTION, "vtable_slot", cands)

    def _propagate_calls(self) -> int:
        fmap, frev = self.fwd[FUNCTION], self.rev[FUNCTION]
        cands: Candidates = {}
        for s, t in list(fmap.items()):
            fs, ft = self.src.functions.get(s), self.tgt.functions.get(t)
            if fs is None or ft is None:
                continue
            conf = self._conf(FUNCTION, s)

            # callees: order of first call is meaningful
            cs, ct = fs.internal_callees, ft.internal_callees
            us = [c for c in cs if c not in fmap]
            ut = [c for c in ct if c not in frev]
            if len(us) == 1 and len(ut) == 1:
                if self._plausible(us[0], ut[0]):
                    self._add(cands, us[0], ut[0], conf * DECAY_CALLEE_SINGLE)
            elif us and len(us) == len(ut) and len(cs) == len(ct):
                # same shape: matched callees line up and unmatched ones are in the same slots
                aligned = all(
                    (a in fmap) == (b in frev) and (a not in fmap or fmap[a] == b)
                    for a, b in zip(cs, ct)
                )
                if aligned:
                    for a, b in zip(us, ut):
                        if self._plausible(a, b):
                            self._add(cands, a, b, conf * DECAY_CALLEE_POSITIONAL)

            # callers: order is not meaningful, only the single-candidate rule applies
            rs = [c for c in self.src.callers.get(s, []) if c not in fmap]
            rt = [c for c in self.tgt.callers.get(t, []) if c not in frev]
            if len(rs) == 1 and len(rt) == 1 and self._plausible(rs[0], rt[0]):
                self._add(cands, rs[0], rt[0], conf * DECAY_CALLER_SINGLE)
        return self._accept(FUNCTION, "callgraph", cands)

    def _propagate_data_refs(self) -> int:
        dmap, drev = self.fwd[DATA], self.rev[DATA]
        cands: Candidates = {}
        for s, t in list(self.fwd[FUNCTION].items()):
            fs, ft = self.src.functions.get(s), self.tgt.functions.get(t)
            if fs is None or ft is None:
                continue
            conf = self._conf(FUNCTION, s)
            rs = [d for d in fs.data_refs if d in self.src.data]
            rt = [d for d in ft.data_refs if d in self.tgt.data]
            us = [d for d in rs if d not in dmap]
            ut = [d for d in rt if d not in drev]
            if len(us) == 1 and len(ut) == 1:
                if self._data_compatible(us[0], ut[0]):
                    self._add(cands, us[0], ut[0], conf * DECAY_DATA_REF_SINGLE)
            elif us and len(us) == len(ut) and len(rs) == len(rt):
                aligned = all(
                    (a in dmap) == (b in drev)
                    and (a not in dmap or dmap[a] == b)
                    and self._data_compatible(a, b)
                    for a, b in zip(rs, rt)
                )
                if aligned:
                    for a, b in zip(us, ut):
                        self._add(cands, a, b, conf * DECAY_DATA_REF_POSITIONAL)
        return self._accept(DATA, "data_ref", cands)

    def _propagate_data_referrers(self) -> int:
        fmap, frev = self.fwd[FUNCTION], self.rev[FUNCTION]
        cands: Candidates = {}
        for s, t in list(self.fwd[DATA].items()):
            ds, dt = self.src.data.get(s), self.tgt.data.get(t)
            if ds is None or dt is None:
                continue
            rs = [f for f in ds.referenced_by if f not in fmap and f in self.src.functions]
            rt = [f for f in dt.referenced_by if f not in frev and f in self.tgt.functions]
            if len(rs) == 1 and len(rt) == 1 and self._plausible(rs[0], rt[0]):
                self._add(cands, rs[0], rt[0], self._conf(DATA, s) * DECAY_DATA_REFERRER)
        return self._accept(FUNCTION, "data_referrer", cands)

    def _source_lines(self, build: Build) -> Dict[str, Dict[str, int]]:
        """source file path -> {function: first line it reports for that file}."""
        cache = self._line_cache.get(id(build))
        if cache is None:
            cache = defaultdict(dict)
            for a, f in build.functions.items():
                for text, n in f.string_args:
                    if _looks_like_source_path(text):
                        prev = cache[text].get(a)
                        if prev is None or n < prev:
                            cache[text][a] = n
            self._line_cache[id(build)] = cache
        return cache

    def _propagate_source_order(self) -> int:
        """Pair functions of one source file by the order of the line numbers they report.

        Lines shift between builds, but their order does not. For each file path, the
        functions reporting it are sorted by line in both builds; between two functions that
        are already paired (or at either end), runs with the same number of unpaired
        functions, in strictly increasing line order, are paired in order.
        """
        fmap, frev = self.fwd[FUNCTION], self.rev[FUNCTION]
        src_files, tgt_files = self._source_lines(self.src), self._source_lines(self.tgt)
        cands: Candidates = {}
        for path in src_files.keys() & tgt_files.keys():
            s_list = sorted(src_files[path].items(), key=lambda kv: (kv[1], kv[0]))
            t_list = sorted(tgt_files[path].items(), key=lambda kv: (kv[1], kv[0]))
            t_pos = {a: i for i, (a, _) in enumerate(t_list)}
            # anchors: paired functions present in both lists, in source order
            anchors = [
                (i, t_pos[fmap[a]]) for i, (a, _) in enumerate(s_list) if fmap.get(a) in t_pos
            ]
            if any(b[1] <= a[1] for a, b in zip(anchors, anchors[1:])):
                continue  # order disagrees; leave this file alone
            bounds = [(-1, -1)] + anchors + [(len(s_list), len(t_list))]
            for (si, ti), (sj, tj) in zip(bounds, bounds[1:]):
                seg_s = [x for x in s_list[si + 1 : sj] if x[0] not in fmap]
                seg_t = [x for x in t_list[ti + 1 : tj] if x[0] not in frev]
                if not seg_s or len(seg_s) != len(seg_t):
                    continue
                if not (_strictly_increasing(seg_s) and _strictly_increasing(seg_t)):
                    continue
                inner = [
                    self._conf(FUNCTION, s_list[k][0]) for k in (si, sj) if 0 <= k < len(s_list)
                ]
                conf = min(inner) * DECAY_SOURCE_ORDER if inner else CONF_SOURCE_ORDER
                for (a, _), (b, _) in zip(seg_s, seg_t):
                    if self._plausible(a, b):
                        self._add(cands, a, b, conf)
        return self._accept(FUNCTION, "source_order", cands)

    def _propagate_neighbors(self) -> int:
        """Pair runs of unmatched functions that sit between the same matched neighbours.

        Builds of the same program keep the link order of most functions, so when source
        functions A < x1..xn < B and target A' < y1..yn < B' (A~A', B~B') contain the same
        number of unmatched functions, xi pairs with yi if their sizes are similar.
        """
        fmap, frev = self.fwd[FUNCTION], self.rev[FUNCTION]
        src_order = _address_order(self.src.functions)
        tgt_order = _address_order(self.tgt.functions)
        tgt_index = {a: i for i, a in enumerate(tgt_order)}
        cands: Candidates = {}
        prev = None  # (source index, target index) of the previous matched function
        for i, a in enumerate(src_order):
            b = fmap.get(a)
            if b is None or b not in tgt_index:
                continue
            j = tgt_index[b]
            if prev is not None:
                pi, pj = prev
                gap_s = src_order[pi + 1 : i]
                gap_t = tgt_order[pj + 1 : j] if j > pj else []
                if len(gap_s) != len(gap_t):
                    # a code entry present in only one build shifts the count; retry with
                    # real functions only
                    gap_s = [a for a in gap_s if self.src.functions[a].defined]
                    gap_t = [b for b in gap_t if self.tgt.functions[b].defined]
                if (
                    gap_s
                    and len(gap_s) == len(gap_t) <= self.cfg.max_neighbor_gap
                    and not any(t in frev for t in gap_t)
                ):
                    conf = (
                        min(self._conf(FUNCTION, src_order[pi]), self._conf(FUNCTION, a))
                        * DECAY_NEIGHBOR
                    )
                    for x, y in zip(gap_s, gap_t):
                        if self._similar_size(x, y):
                            self._add(cands, x, y, conf)
            prev = (i, j)
        return self._accept(FUNCTION, "neighbor", cands)

    def _similar_size(self, s: str, t: str) -> bool:
        fs, ft = self.src.functions[s], self.tgt.functions[t]
        if fs.is_thunk != ft.is_thunk:
            return False
        if not fs.defined or not ft.defined:
            return self._heads_agree(fs, ft)  # a code entry's size covers only its head
        if fs.size == 0 or ft.size == 0:
            return fs.size == ft.size
        return max(fs.size, ft.size) / min(fs.size, ft.size) <= self.cfg.neighbor_size_ratio


_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".m", ".mm")


def _looks_like_source_path(text: str) -> bool:
    return ("\\" in text or "/" in text) and text.lower().endswith(_SOURCE_SUFFIXES)


def _strictly_increasing(items: List[Tuple[str, int]]) -> bool:
    return all(a[1] < b[1] for a, b in zip(items, items[1:]))


def _address_order(items: dict) -> List[str]:
    def key(a: str):
        try:
            return (0, int(a.rsplit(":", 1)[-1], 16), a)
        except ValueError:
            return (1, 0, a)

    return sorted(items, key=key)


def match(source: Build, target: Build, config: Optional[MatchConfig] = None) -> MatchResult:
    return Matcher(source, target, config).run()
