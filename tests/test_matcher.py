from ghidra_matching.matcher import DATA, FUNCTION, MatchConfig, match

from .helpers import build, data, fn


def pairs_of(result, kind=FUNCTION):
    return {p.source: (p.target, p.method) for p in result.pairs if p.kind == kind}


def test_name_anchor_requires_unique_names():
    src = build("s", [fn("1", "main"), fn("2", "dup"), fn("3", "dup")])
    tgt = build("t", [fn("a", "main"), fn("b", "dup"), fn("c", "dup")])
    got = pairs_of(match(src, tgt, MatchConfig(propagate=False)))
    assert got == {"1": ("a", "name")}


def test_string_set_anchor():
    src = build("s", [fn("1", string_refs=["hello world", "bye"]), fn("2", string_refs=["x"])])
    tgt = build("t", [fn("b", string_refs=["bye", "hello world"]), fn("a", string_refs=["x"])])
    got = pairs_of(match(src, tgt, MatchConfig(propagate=False)))
    # "x" is shorter than min_string_length and is ignored
    assert got == {"1": ("b", "string_set")}


def test_unique_string_votes_survive_extra_strings():
    src = build(
        "s", [fn("1", string_refs=["config.ini", "common"]), fn("2", string_refs=["common"])]
    )
    tgt = build(
        "t",
        [
            fn("a", string_refs=["config.ini", "common", "new in v2"]),
            fn("b", string_refs=["common", "something else"]),
        ],
    )
    got = pairs_of(match(src, tgt, MatchConfig(propagate=False)))
    assert got["1"] == ("a", "unique_string")


def test_conflicting_unique_string_votes_are_rejected():
    src = build("s", [fn("1", string_refs=["alpha!", "beta!!"])])
    tgt = build("t", [fn("a", string_refs=["alpha!"]), fn("b", string_refs=["beta!!"])])
    assert pairs_of(match(src, tgt, MatchConfig(propagate=False))) == {}


def test_body_hash_anchor_needs_min_instructions():
    src = build(
        "s", [fn("1", mnemonic_hash="h1", insn_count=50), fn("2", mnemonic_hash="h2", insn_count=3)]
    )
    tgt = build(
        "t", [fn("a", mnemonic_hash="h1", insn_count=50), fn("b", mnemonic_hash="h2", insn_count=3)]
    )
    got = pairs_of(match(src, tgt, MatchConfig(propagate=False)))
    assert got == {"1": ("a", "body_hash")}


def test_callgraph_propagation_single_and_positional():
    src = build(
        "s",
        [
            fn("1", "root", callees=["2", "3", "4"]),
            fn("2", callees=["5"]),
            fn("3"),
            fn("4"),
            fn("5"),
        ],
    )
    tgt = build(
        "t",
        [
            fn("a", "root", callees=["b", "c", "d"]),
            fn("b", callees=["e"]),
            fn("c"),
            fn("d"),
            fn("e"),
        ],
    )
    got = pairs_of(match(src, tgt))
    assert {s: t for s, (t, _) in got.items()} == {"1": "a", "2": "b", "3": "c", "4": "d", "5": "e"}
    assert got["2"][1] == "callgraph"


def test_callgraph_respects_size_ratio():
    src = build("s", [fn("1", "root", callees=["2"]), fn("2", size=10)])
    tgt = build("t", [fn("a", "root", callees=["b"]), fn("b", size=1000)])
    got = pairs_of(match(src, tgt))
    assert "2" not in got


def test_vtable_votes_and_slot_propagation():
    # Foo vtable: slot0 is anchored by string, slot1/2 are only known through the vtable.
    src = build(
        "s",
        [
            fn("1", string_refs=["Foo::Foo destructor"], vtable_slots=[("v", 0)]),
            fn("2", vtable_slots=[("v", 1)]),
            fn("3", vtable_slots=[("v", 2)]),
        ],
        [data("v", kind="vtable", slots=["1", "2", "3"])],
    )
    tgt = build(
        "t",
        [
            fn("a", string_refs=["Foo::Foo destructor"], vtable_slots=[("V", 0)]),
            fn("b", vtable_slots=[("V", 1)]),
            fn("c", vtable_slots=[("V", 2)]),
        ],
        [data("V", kind="vtable", slots=["a", "b", "c"])],
    )
    result = match(src, tgt)
    assert pairs_of(result, DATA) == {"v": ("V", "vtable_votes")}
    funcs = pairs_of(result)
    assert funcs["2"] == ("b", "vtable_slot")
    assert funcs["3"] == ("c", "vtable_slot")


def test_vtable_name_anchor_from_rtti_labels():
    src = build(
        "s",
        [fn("1"), fn("2")],
        [data("v", "vftable", namespace="Foo", kind="vtable", slots=["1", "2"])],
    )
    tgt = build(
        "t",
        [fn("a"), fn("b")],
        [data("V", "vftable", namespace="Foo", kind="vtable", slots=["a", "b"])],
    )
    funcs = pairs_of(match(src, tgt))
    assert funcs == {"1": ("a", "vtable_slot"), "2": ("b", "vtable_slot")}


def test_data_refs_and_referrers():
    src = build(
        "s",
        [fn("1", "init", data_refs=["g1"]), fn("2", data_refs=["g2"])],
        [data("g1", "g_config"), data("g2", "g_state", referenced_by=["2"])],
    )
    tgt = build(
        "t",
        [fn("a", "init", data_refs=["G1"]), fn("b", data_refs=["G2"])],
        [data("G1"), data("G2", referenced_by=["b"])],
    )
    result = match(src, tgt)
    assert pairs_of(result, DATA)["g1"] == ("G1", "data_ref")
    # g2 is not reachable from a matched function, so "2" stays unmatched
    assert "2" not in pairs_of(result)


def test_blind_mode_ignores_names():
    src = build("s", [fn("1", "main")])
    tgt = build("t", [fn("a", "main")])
    assert match(src, tgt, MatchConfig(use_names=False)).pairs == []


def test_confidence_decays_along_chains():
    src = build("s", [fn("1", "root", callees=["2"]), fn("2", callees=["3"]), fn("3")])
    tgt = build("t", [fn("a", "root", callees=["b"]), fn("b", callees=["c"]), fn("c")])
    conf = {p.source: p.confidence for p in match(src, tgt).pairs}
    assert conf["1"] > conf["2"] > conf["3"]


def test_stats_report_name_agreement():
    src = build("s", [fn("1", "main", callees=["2"]), fn("2", "helper")])
    tgt = build("t", [fn("a", "main", callees=["b"]), fn("b", "helper_renamed")])
    stats = match(src, tgt).stats()[FUNCTION]
    assert stats["matched"] == 2
    assert stats["names_agree"] == 1
    assert stats["names_disagree"] == 1


def test_stats_ignore_analysis_names():
    # analysis names embed addresses and differ between builds without being wrong
    src = build(
        "s", [fn("1", "main", callees=["2"]), fn("2", "caseD_1400a", name_source="ANALYSIS")]
    )
    tgt = build(
        "t", [fn("a", "main", callees=["b"]), fn("b", "caseD_1400b", name_source="ANALYSIS")]
    )
    stats = match(src, tgt).stats()[FUNCTION]
    assert stats["matched"] == 2
    assert stats["names_disagree"] == 0
    assert stats["source_with_user_markup"] == 1


def test_neighbor_pairing_between_matched_functions():
    # 2..4 have nothing distinctive but sit between the same matched neighbours
    src = build(
        "s",
        [
            fn("1000", "first"),
            fn("1010", size=8),
            fn("1020", size=36),
            fn("1030", size=36),
            fn("1040", "last"),
        ],
    )
    tgt = build(
        "t",
        [
            fn("2000", "first"),
            fn("2010", size=8),
            fn("2020", size=36),
            fn("2030", size=40),
            fn("2040", "last"),
        ],
    )
    got = pairs_of(match(src, tgt))
    assert got["1010"] == ("2010", "neighbor")
    assert got["1020"] == ("2020", "neighbor")
    assert got["1030"] == ("2030", "neighbor")
    assert pairs_of(match(src, tgt, MatchConfig(use_neighbors=False))).keys() == {"1000", "1040"}


def test_neighbor_pairing_needs_equal_gap_and_similar_size():
    src = build("s", [fn("1000", "a"), fn("1010", size=8), fn("1040", "b")])
    uneven = build("t", [fn("2000", "a"), fn("2010", size=8), fn("2020", size=8), fn("2040", "b")])
    assert "1010" not in pairs_of(match(src, uneven))
    resized = build("t", [fn("2000", "a"), fn("2010", size=100), fn("2040", "b")])
    assert "1010" not in pairs_of(match(src, resized))


def test_string_args_separate_same_strings_at_different_lines():
    path = "D:\\src\\List.h"
    src = build(
        "s",
        [
            fn("1", string_refs=["cond", path], string_args=[("cond", 1), (path, 157)]),
            fn("2", string_refs=["cond", path], string_args=[("cond", 1), (path, 170)]),
        ],
    )
    tgt = build(
        "t",
        [
            fn("b", string_refs=["cond", path], string_args=[("cond", 1), (path, 170)]),
            fn("a", string_refs=["cond", path], string_args=[("cond", 1), (path, 157)]),
        ],
    )
    got = pairs_of(match(src, tgt, MatchConfig(propagate=False)))
    assert got == {"1": ("a", "string_args"), "2": ("b", "string_args")}


def test_source_order_pairs_by_line_order_within_file():
    path = "D:\\src\\Combat\\CmbtCliMsg.cpp"
    # lines moved by a few between builds; order is kept; "anchor" pairs by name
    src = build(
        "s",
        [
            fn("1", string_args=[(path, 0x30)]),
            fn("2", "anchor", string_args=[(path, 0x35)]),
            fn("3", string_args=[(path, 0x50)]),
            fn("4", string_args=[(path, 0x60)]),
        ],
    )
    tgt = build(
        "t",
        [
            fn("a", string_args=[(path, 0x32)]),
            fn("b", "anchor", string_args=[(path, 0x37)]),
            fn("c", string_args=[(path, 0x58)]),
            fn("d", string_args=[(path, 0x66)]),
        ],
    )
    got = pairs_of(match(src, tgt, MatchConfig(use_neighbors=False)))
    assert {k: v[0] for k, v in got.items()} == {"1": "a", "2": "b", "3": "c", "4": "d"}
    assert got["3"][1] == "source_order"
