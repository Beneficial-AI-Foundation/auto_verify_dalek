#!/usr/bin/env python3
"""Build the graph-top catalog over the Aeneas-extracted functions.

Judgement (DEC-04 follow-up; companion to api_top.py):
  api-top   (harness/api_top.py)  = user-facing pub API surface, ignores callers.
  graph-top (this script)         = extracted functions that no OTHER extracted
    function depends on.  Because every Rust function of the crate has exactly
    one `Funs.lean` def, this is the Rust "not called by any other crate
    function" set, computed on the Lean side where the edges are exact
    (operator calls are already resolved to the impl method by Aeneas).

Node set: rows of functions.json (one per Aeneas def), minus
  * trait-instance records (rust_name ends in `}`, or -- when the probe
    truncated rust_name at a `(` -- the row is the parent of a
    `<record>.<method>` row; Lean value of the trait structure, no logic of
    its own);
  * `*_loop` bodies (Aeneas-split loop of the parent function).

Edge rule (functions.json `dependencies`, caller -> callee):
  * an edge from an instance record does NOT count as a call; instead the
    record is transparent: whoever depends on the record depends on every
    method it bundles.  Records depend on other records (supertraits, e.g.
    `CoreCmpEq -> CoreCmpPartialEq`), so transparency is transitive.
  * an edge from `P_loop` counts as an edge from `P`.
  * self edges are ignored.

Hand-written Lean (FunsExternal.lean, Aux.lean) cannot import Funs.lean,
so a call from there would be invisible to functions.json.  `external_lean_refs`
lists the hand-written files that mention a top's Lean name or its instance
record; verified 2026-09-11 that the list is empty for every top (earlier
`external_caller_suspect` flags on eq / conditional_select / ct_eq were false
alarms: the default-method models take the instance record as an argument,
and no extracted function passes those records).

Categories (Rust side, no API judgement):
  trait_impl / operator_forwarder  -- trait methods (macros.rs shells split out)
  inherent_pub / inherent_pub_crate / inherent_private
      -- inherent fns by the visibility keyword on the `fn` line.  `pub_module`
      says whether the owning module is exported from lib.rs; `inherent_pub`
      with pub_module=false is a backend fn, crate-internal in effect.

Cross-check hint: `rust_grep_hits` counts `name(` occurrences in the crate's
non-test source outside the definition line.  Meaningless for operator
methods (`add`, `mul`, ...) and other trait methods, so it is only reported
for the inherent categories.  It matches by bare method name, so
same-named methods on other types inflate it (verified 2026-09-10: the three
`internal` tops -- deprecated `FieldElement51::as_bytes`,
`ProjectivePoint::as_extended` (all hits are `CompletedPoint::as_extended`),
`Scalar52::square` (test-only) -- are genuine tops).

Inputs (pinned):   functions.json, curve25519-dalek/src/ (repo copy),
                   Curve25519Dalek/FunsExternal.lean, Curve25519Dalek/Aux.lean
Outputs:           .verilib/top_level_funs.json, .verilib/top_level_funs.md
"""

import collections
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api_top import owning_module, self_type, load_pub_types  # noqa: E402

RUST_SRC = os.path.join(REPO, "curve25519-dalek", "src")

# hand-written Lean that may call into Funs.lean without functions.json seeing it
HAND_WRITTEN_LEAN = ["Curve25519Dalek/FunsExternal.lean", "Curve25519Dalek/Aux.lean"]
LEAN_NS = "curve25519_dalek."
FN_LINE_RE = re.compile(r"^\s*(pub(?:\([^)]*\))?)?\s*(?:const\s+)?(?:unsafe\s+)?fn\s+(\w+)")

TRAIT_IMPL_RE = re.compile(r"\{.+ for .+\}")


_LEAN_NAMES = set()      # filled by load_functions(); used by is_record


def is_record(entry):
    rn = entry["rust_name"]
    if rn.count("{") == rn.count("}"):          # intact rust_name
        return rn.endswith("}")
    # rust_name truncated by the probe at the first '(' (e.g.
    # `TryFrom<&0 ([u8]), ...>`, `FnOnce<([u8; 32],)>`): the record and its
    # methods then share one rust_name, so fall back to the Lean-name shape --
    # a record is the parent of some `<record>.<method>` row.
    prefix = entry["lean_name"] + "."
    return any(n.startswith(prefix) for n in _LEAN_NAMES)


def is_loop(entry):
    return entry["lean_name"].endswith("_loop")


def method_name(entry):
    return entry["rust_name"].rsplit("::", 1)[-1]


def is_trait_method(entry):
    return ".Insts." in entry["lean_name"] or (
        TRAIT_IMPL_RE.search(entry["rust_name"]) is not None)


def load_functions():
    with open(os.path.join(REPO, "functions.json")) as fh:
        rows = json.load(fh)["functions"]
    _LEAN_NAMES.clear()
    _LEAN_NAMES.update(r["lean_name"] for r in rows)
    return rows


def build_callers(rows):
    """callee -> set(caller) after record transparency and loop folding."""
    by_name = {r["lean_name"]: r for r in rows}
    records = {n for n, r in by_name.items() if is_record(r)}
    raw = collections.defaultdict(set)          # callee -> direct dependants
    for r in rows:
        for d in r.get("dependencies") or []:
            raw[d].add(r["lean_name"])

    def real_callers(node, seen):
        """Non-record dependants of `node`, seeing through records."""
        out = set()
        for c in raw.get(node, ()):
            if c in records:
                if c not in seen:
                    seen.add(c)
                    out |= real_callers(c, seen)
            else:
                out.add(c[:-5] if c.endswith("_loop") else c)
        return out

    callers = {}
    for n in by_name:
        cs = real_callers(n, set())
        cs.discard(n)
        callers[n] = cs
    return callers


def rust_visibility(entry):
    """Visibility keyword on the `fn` line of the entry's source range."""
    a, b = (int(x[1:]) for x in entry["lines"].split("-"))
    with open(os.path.join(REPO, entry["source"])) as fh:
        # functions.json ranges are sometimes off by one (they start at the
        # body); look a few lines above the range for the `fn` line.
        lines = fh.read().split("\n")[max(a - 4, 0):b]
    want = method_name(entry)
    for line in lines:
        m = FN_LINE_RE.match(line)
        if m and m.group(2) == want:
            kw = m.group(1) or ""
            if kw == "pub":
                return "pub"
            if kw.startswith("pub("):
                return "pub_crate"        # pub(crate) / pub(super)
            return "private"
    raise ValueError(f"no `fn {want}` in {entry['source']}:{entry['lines']}")


def categorize(entry):
    if is_trait_method(entry):
        if entry["source"].endswith("macros.rs"):
            return "operator_forwarder"
        return "trait_impl"
    return "inherent_" + rust_visibility(entry)


def is_pub_module(entry, pub_types):
    module = owning_module(entry["rust_name"])
    st = self_type(entry["rust_name"])
    return bool(module and (st is None or st in pub_types))


_LEAN_TEXT = {}


def hand_written_lean():
    if not _LEAN_TEXT:
        for rel in HAND_WRITTEN_LEAN:
            with open(os.path.join(REPO, rel)) as fh:
                text = fh.read()
            text = re.sub(r"/-.*?-/", "", text, flags=re.S)
            text = re.sub(r"--[^\n]*", "", text)
            _LEAN_TEXT[rel] = text
    return _LEAN_TEXT


def external_lean_refs(lean_name):
    """Hand-written Lean files mentioning `lean_name` or its instance record.

    Files sit inside `namespace curve25519_dalek`, so both the qualified and
    the namespace-relative spelling are checked."""
    short = lean_name[len(LEAN_NS):] if lean_name.startswith(LEAN_NS) else lean_name
    targets = {short}
    if ".Insts." in short:
        targets.add(short.rsplit(".", 1)[0])       # the trait-instance record
    pats = [re.compile(r"(?<![\w.'])(?:" + re.escape(LEAN_NS) + r")?"
                       + re.escape(t) + r"(?![\w.'])") for t in targets]
    return sorted(rel for rel, text in hand_written_lean().items()
                  if any(p.search(text) for p in pats))


_SRC_CACHE = {}


def non_test_source():
    """Concatenated crate source with each file cut at its first #[cfg(test)]."""
    if _SRC_CACHE:
        return _SRC_CACHE["src"]
    chunks = []
    for root, _, files in os.walk(RUST_SRC):
        for f in files:
            if not f.endswith(".rs"):
                continue
            with open(os.path.join(root, f)) as fh:
                text = fh.read()
            cut = text.find("#[cfg(test)]")
            chunks.append(text if cut < 0 else text[:cut])
    _SRC_CACHE["src"] = "\n".join(chunks)
    return _SRC_CACHE["src"]


def rust_grep_hits(name):
    src = non_test_source()
    pat = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    hits = 0
    for line in src.splitlines():
        if re.search(r"\bfn\s+" + re.escape(name) + r"\b", line):
            continue
        hits += len(pat.findall(line))
    return hits


def main():
    rows = load_functions()
    pub_types = load_pub_types()
    if not pub_types:                       # fall back to the repo copy
        from api_top import PUB_MODULE_FILES, PUB_TYPE_RE
        for rel in PUB_MODULE_FILES:
            with open(os.path.join(REPO, rel)) as fh:
                pub_types.update(PUB_TYPE_RE.findall(fh.read()))
    callers = build_callers(rows)

    candidates = [r for r in rows if not is_record(r) and not is_loop(r)]
    top = []
    for r in candidates:
        if callers[r["lean_name"]]:
            continue
        cat = categorize(r)
        name = method_name(r)
        inherent = cat.startswith("inherent_")
        row = {
            "lean_name": r["lean_name"],
            "rust_name": r["rust_name"],
            "category": cat,
            "pub_module": is_pub_module(r, pub_types) if inherent else None,
            "specified": r["specified"],
            "verified": r["verified"],
            "is_hidden": r["is_hidden"],
            "is_ignored": r["is_ignored"],
            "is_extraction_artifact": r["is_extraction_artifact"],
            "source": r["source"],
            "lines": r["lines"],
            "external_lean_refs": external_lean_refs(r["lean_name"]),
            "rust_grep_hits": rust_grep_hits(name) if inherent else None,
        }
        top.append(row)
    top.sort(key=lambda x: (x["category"], x["lean_name"]))

    counts = collections.Counter(x["category"] for x in top)
    out = {
        "method": "functions.json row (Aeneas def) with no dependant among the "
                  "other rows; trait-instance records are transparent "
                  "(transitively), *_loop bodies fold into their parent, "
                  "records and loop bodies are not candidates",
        "source": "functions.json",
        "rows_total": len(rows),
        "records_excluded": sum(1 for r in rows if is_record(r)),
        "loop_bodies_excluded": sum(1 for r in rows if is_loop(r)),
        "candidates": len(candidates),
        "top_level_count": len(top),
        "by_category": dict(counts),
        "external_lean_checked": HAND_WRITTEN_LEAN,
        "external_lean_ref_count": sum(1 for x in top if x["external_lean_refs"]),
        "top_level": top,
    }
    os.makedirs(os.path.join(REPO, ".verilib"), exist_ok=True)
    with open(os.path.join(REPO, ".verilib", "top_level_funs.json"), "w") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)

    titles = {
        "inherent_pub": "固有方法，`pub`",
        "inherent_pub_crate": "固有方法，`pub(crate)`",
        "inherent_private": "固有方法，私有",
        "trait_impl": "trait 实现方法",
        "operator_forwarder": "运算符转发壳（macros.rs 生成）",
    }
    ext_n = out["external_lean_ref_count"]
    md = [
        "# graph-top：Funs.lean 中不被其他抽取函数依赖的函数",
        "",
        f"来源: `functions.json`（{len(rows)} 行；剔除 {out['records_excluded']} 个 "
        f"trait 实例记录、{out['loop_bodies_excluded']} 个 `_loop` 体后 "
        f"{len(candidates)} 个候选）；共 **{len(top)}** 条。",
        "判定: 候选函数不被任何其他候选函数依赖。实例记录透传（含 supertrait 链），"
        "`P_loop` 的依赖记为 `P` 的依赖。",
        "分类只按 Rust 源里 `fn` 行的可见性关键字，不判断是否为 API 入口；`模块` 列 = 所属模块是否由 lib.rs 导出"
        "（`pub` 但模块未导出 = backend 内部函数）。"
        f"`external_lean_refs` = 手写 Lean（{', '.join(f'`{f}`' for f in HAND_WRITTEN_LEAN)}）"
        f"中提到该函数或其实例记录的文件；本次 {ext_n} 条非空"
        "（手写默认方法模型以实例记录为参数，抽取代码从未传入这些记录）。"
        "`rust_grep_hits` = crate 非测试源码中 `name(` 的出现次数"
        "（定义行除外），仅作交叉核对提示；按方法名匹配，同名方法（如 `CompletedPoint::as_extended` 与 `ProjectivePoint::as_extended`）会互相污染，高计数不等于有调用者。",
        "",
    ]
    for cat in ("inherent_pub", "inherent_pub_crate", "inherent_private",
                "trait_impl", "operator_forwarder"):
        items = [x for x in top if x["category"] == cat]
        if not items:
            continue
        md += [f"## {titles[cat]}（{len(items)} 条）", ""]
        if cat.startswith("inherent_"):
            md += ["| Lean 名 | spec | 模块 | grep | 位置 |", "|---|---|---|---|---|"]
            for x in items:
                md.append(f"| `{x['lean_name']}` | {'✓' if x['specified'] else ''} "
                          f"| {'导出' if x['pub_module'] else 'backend'} "
                          f"| {x['rust_grep_hits']} | {x['source']}:{x['lines']} |")
        else:
            md += ["| Lean 名 | spec | 手写 Lean 引用 | 位置 |", "|---|---|---|---|"]
            for x in items:
                md.append(f"| `{x['lean_name']}` | {'✓' if x['specified'] else ''} "
                          f"| {', '.join(x['external_lean_refs'])} "
                          f"| {x['source']}:{x['lines']} |")
        md.append("")
    with open(os.path.join(REPO, ".verilib", "top_level_funs.md"), "w") as fh:
        fh.write("\n".join(md))

    print(f"top-level: {len(top)} / {len(candidates)} candidates "
          f"({dict(counts)})")


if __name__ == "__main__":
    main()
