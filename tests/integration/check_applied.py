"""Verify that the apply step transferred the source's user markup, and nothing else.

Usage: check_applied.py <source.markup.csv> <target_before.markup.csv>
                        <target_after.markup.csv> <pairs.csv>

The dumps come from DumpMarkup.java; pairs.csv is the markup-only pairing table.
"""

from __future__ import annotations

import csv
import sys
from typing import Dict, List, Tuple

Rows = Dict[Tuple[str, str], dict]


def load(path: str) -> Rows:
    with open(path, newline="", encoding="utf-8") as fh:
        return {(r["kind"], r["key"]): r for r in csv.DictReader(fh)}


def main(source_csv: str, before_csv: str, after_csv: str, pairs_csv: str) -> int:
    src, before, after = load(source_csv), load(before_csv), load(after_csv)
    with open(pairs_csv, newline="", encoding="utf-8") as fh:
        pairs = list(csv.DictReader(fh))

    failures: List[str] = []
    checked: Dict[str, int] = {"name": 0, "signature": 0, "label": 0, "datatype": 0, "type": 0}

    def expect(what: str, ok: bool, message: str) -> None:
        checked[what] += 1
        if not ok:
            failures.append(f"{what}: {message}")

    touched = set()
    for p in pairs:
        markup = set(p["markup"].split("+")) if p["markup"] else set()
        s_addr, t_addr = p["source_address"], p["target_address"]
        if p["kind"] == "function":
            touched.add(t_addr)
            s, a = src[("function", s_addr)], after[("function", t_addr)]
            if "name" in markup:
                expect("name", a["name"] == s["name"], f"{t_addr} is {a['name']}, want {s['name']}")
            if "signature" in markup or "name" in markup:
                s_proto, a_proto = s["detail"].split("|")[0], a["detail"].split("|")[0]
                expect("signature", s_proto == a_proto, f"{t_addr} is {a_proto}, want {s_proto}")
        else:
            s = src.get(("label", s_addr))
            a = after.get(("label", t_addr))
            if "label" in markup:
                expect(
                    "label",
                    a is not None and a["name"] == s["name"],
                    f"{t_addr} is {a and a['name']}, want {s and s['name']}",
                )
            if "datatype" in markup and s is not None:
                expect(
                    "datatype",
                    a is not None and a["detail"] == s["detail"],
                    f"{t_addr} is {a and a['detail']}, want {s['detail']}",
                )

    for key, row in src.items():
        if key[0] == "type":
            got = after.get(key)
            expect("type", got is not None and got["detail"] == row["detail"], f"{key[1]}: {got}")

    collateral = [
        f"{k[1]}: {row['name']} -> {after[k]['name']}"
        for k, row in before.items()
        if k[0] == "function" and k[1] not in touched and after[k]["name"] != row["name"]
    ]

    print("checked:", ", ".join(f"{k} {v}" for k, v in checked.items()))
    for f in failures:
        print("FAIL", f)
    for c in collateral:
        print("FAIL renamed without user markup:", c)
    missing = [k for k, v in checked.items() if v == 0]
    if missing:
        print("FAIL nothing checked for:", ", ".join(missing))
    return 1 if failures or collateral or missing else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:5]))
