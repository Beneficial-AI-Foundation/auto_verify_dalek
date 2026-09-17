#!/usr/bin/env python3
"""graph-top catalog computed from the probe-lean extract (standalone).

Same judgement, node set, edge rules, categories and output format as
lean_top.py, but the input is .verilib/probes/lean_<pkg>_<ver>.json
(schema probe-lean/extract 2.0) instead of functions.json, and this script
imports nothing from the other harness scripts.

Judgement (DEC-04 follow-up):
  graph-top = extracted functions that no OTHER extracted function depends
  on.  Every Rust function of the crate has exactly one Funs.lean def, so
  this is the Rust "not called by any other crate function" set, computed on
  the Lean side where the edges are exact.

Node set: Funs.lean defs of the probe whose Rust source lives in the crate
(`curve25519-dalek/...`), minus
  * trait-instance records (Lean value of the trait structure, no logic;
    rust_name ends in `}`);
  * `*_loop` bodies (Aeneas-split loop of the parent function).
Impls the probe records for foreign types (`bool`, `u8`, `RangeFull`,
`subtle::Choice`, zeroize blanket; source under /rustc or /cargo/registry) are
dropped up front; they are records whose methods live in FunsExternal.lean,
so keeping them would not change the result either.

Edge rule (probe `dependencies` + `term-dependencies`, caller -> callee):
  * an edge from an instance record does NOT count as a call; the record is
    transparent: whoever depends on the record depends on every method it
    bundles.  Records depend on records (supertraits), so transitively.
  * an edge from `P_loop` counts as an edge from `P`.
  * self edges are ignored.

What the probe lacks and where it is taken from:
  * rust_name and the Rust line range -- from the Aeneas docstring at the top
    of every def's `code-text` range in Funs.lean:
        /-- [<rust path>]:                     (`]: loop N:` for a loop body)
           Source: '<file>', lines A:c-B:d -/  (`Trait implementation: [..]` for a record)
  * calls made inside a `partial_fixpoint` loop body -- probe-lean 0.9.4 lists
    only the auxiliary constant `<loop>.mutual` as that def's dependency and
    has no record for it.  Recovered by scanning the loop body for
    namespace-relative names of other Funs.lean defs (comments stripped).
    Checked 2026-09-14 against the 13 `.mutual` rows of functions.json:
    identical up to one foreign record.  A call through dot-notation on a
    variable (`scalar.as_bytes`) would be missed; none occurs in those bodies.

Categories (Rust side, no API judgement):
  trait_impl / operator_forwarder  -- trait methods (macros.rs shells split out)
  inherent_pub / inherent_pub_crate / inherent_private
      -- inherent fns by the visibility keyword on the `fn` line; `pub_module`
      says whether the owning module is exported from lib.rs.

Inputs (pinned): .verilib/probes/lean_*.json (newest by name),
                 Curve25519Dalek/Funs.lean, curve25519-dalek/src/,
                 Curve25519Dalek/FunsExternal.lean, Curve25519Dalek/Aux.lean
Outputs:         .verilib/top_level_funs_probe.json, .verilib/top_level_funs_probe.md
                 (+ a diff against .verilib/top_level_funs.json when present)
"""

import collections
import glob
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROBE_GLOB = os.path.join(REPO, ".verilib", "probes", "lean_*.json")
FUNS_LEAN = "Curve25519Dalek/Funs.lean"
RUST_SRC = os.path.join(REPO, "curve25519-dalek", "src")
CRATE_SRC_PREFIX = "curve25519-dalek/"
OUT_STEM = "top_level_funs_probe"
REFERENCE = os.path.join(REPO, ".verilib", "top_level_funs.json")

# hand-written Lean that may call into Funs.lean without the probe seeing it
HAND_WRITTEN_LEAN = ["Curve25519Dalek/FunsExternal.lean", "Curve25519Dalek/Aux.lean"]
LEAN_NS = "curve25519_dalek."

# --- Rust-side module / visibility knowledge (mirrors api_top.py) ------------
CRATE = "curve25519_dalek"
PUB_MODULES = {"scalar", "montgomery", "edwards", "ristretto", "constants", "traits"}
EXCLUDED_PREFIXES = (f"{CRATE}::edwards::affine::",)
REEXPORTS = {f"{CRATE}::backend::serial::u64::constants::": "constants"}
PUB_MODULE_FILES = [
    "curve25519-dalek/src/edwards.rs",
    "curve25519-dalek/src/ristretto.rs",
    "curve25519-dalek/src/montgomery.rs",
    "curve25519-dalek/src/scalar.rs",
    "curve25519-dalek/src/constants.rs",
    "curve25519-dalek/src/traits.rs",
]
# api_top.py reads the pub types from this checkout first, then the repo copy
RUST_SRC_ROOTS = [os.path.expanduser("~/curve25519-dalek-lean-verify"), REPO]

TRAIT_IMPL_RE = re.compile(r"\{.+ for .+\}")
SELF_TYPE_TRAIT_RE = re.compile(r" for (?:&[^ (]* ?\()?([\w:]+)")
SELF_TYPE_INHERENT_RE = re.compile(r"\{([\w:]+)\}")
PUB_TYPE_RE = re.compile(r"^\s*pub\s+(?:struct|enum|type)\s+(\w+)", re.M)
FN_LINE_RE = re.compile(r"^\s*(pub(?:\([^)]*\))?)?\s*(?:const\s+)?(?:unsafe\s+)?fn\s+(\w+)")

# --- Funs.lean docstring ----------------------------------------------------
HEADER_RE = re.compile(r"^/--\s*(?:Trait implementation: )?\[(.*)\][^\]]*$")
SOURCE_RE = re.compile(r"^\s*Source: '([^']*)', lines (\d+):\d+-(\d+):\d+")


# ============================================================================
# input: probe -> rows
# ============================================================================

def find_probe():
    files = sorted(glob.glob(PROBE_GLOB))
    if not files:
        sys.exit(f"no probe extract under {os.path.dirname(PROBE_GLOB)}")
    return files[-1]


def strip_lean_comments(text):
    text = re.sub(r"/-.*?-/", "", text, flags=re.S)
    return "\n".join(line.split("--")[0] for line in text.split("\n"))


def parse_docstring(src_lines, start):
    """(rust_name, source, 'La-Lb') from the docstring at 1-based line `start`."""
    head = src_lines[start - 1]
    m = HEADER_RE.match(head)
    if not m:
        raise ValueError(f"{FUNS_LEAN}:{start}: no Aeneas docstring: {head[:80]!r}")
    m2 = SOURCE_RE.match(src_lines[start])
    if not m2:
        raise ValueError(f"{FUNS_LEAN}:{start + 1}: no Source line")
    return m.group(1), m2.group(1), f"L{m2.group(2)}-L{m2.group(3)}"


def load_rows(probe_path):
    """Rows: lean_name, rust_name, source, lines, dependencies, flags."""
    with open(probe_path) as fh:
        probe = json.load(fh)
    data = probe["data"]
    with open(os.path.join(REPO, FUNS_LEAN)) as fh:
        src_lines = fh.read().split("\n")

    funs = {k[len("probe:"):]: v for k, v in data.items()
            if v.get("code-path") == FUNS_LEAN}
    rel_names = {n[len(LEAN_NS):]: n for n in funs if n.startswith(LEAN_NS)}

    def body_calls(name, rec):
        """Funs.lean defs named in the body of `name` (namespace-relative)."""
        s, e = rec["code-text"]["lines-start"], rec["code-text"]["lines-end"]
        body = strip_lean_comments("\n".join(src_lines[s - 1:e]))
        me = name[len(LEAN_NS):]
        out = set()
        for rel, full in rel_names.items():
            if rel == me or me.startswith(rel + "."):
                continue
            if re.search(r"(?<![\w.])" + re.escape(rel) + r"(?![\w.])", body):
                out.add(full)
        return out

    rows, dropped_foreign, recovered = [], [], []
    for name, rec in funs.items():
        if not rec["rust-source"].startswith(CRATE_SRC_PREFIX):
            dropped_foreign.append(name)
            continue
        rust_name, source, lines = parse_docstring(
            src_lines, rec["code-text"]["lines-start"])
        deps = {d[len("probe:"):] for d in
                set(rec["dependencies"]) | set(rec["term-dependencies"])}
        mutual = [d for d in deps if d.endswith(".mutual") and "probe:" + d not in data]
        if mutual:
            deps -= set(mutual)
            deps |= body_calls(name, rec)
            recovered.append(name)
        rows.append({
            "lean_name": name,
            "rust_name": rust_name,
            "source": source,
            "lines": lines,
            "dependencies": sorted(deps),
            "specified": bool(rec.get("specs")),
            "verified": rec["verification-status"] == "verified",
            "verification_status": rec["verification-status"],
            "is_hidden": rec["is-hidden"],
            "is_ignored": rec["is-ignored"],
            "is_extraction_artifact": rec["is-extraction-artifact"],
        })
    return probe, rows, dropped_foreign, recovered


# ============================================================================
# graph: node set and edge rules
# ============================================================================

def is_record(entry):
    return entry["rust_name"].endswith("}")


def is_loop(entry):
    return entry["lean_name"].endswith("_loop")


def method_name(entry):
    return entry["rust_name"].rsplit("::", 1)[-1]


def is_trait_method(entry):
    return ".Insts." in entry["lean_name"] or (
        TRAIT_IMPL_RE.search(entry["rust_name"]) is not None)


def build_callers(rows):
    """callee -> set(caller) after record transparency and loop folding."""
    by_name = {r["lean_name"]: r for r in rows}
    records = {n for n, r in by_name.items() if is_record(r)}
    raw = collections.defaultdict(set)          # callee -> direct dependants
    for r in rows:
        for d in r["dependencies"]:
            raw[d].add(r["lean_name"])

    def real_callers(node, seen):
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


# ============================================================================
# Rust side: visibility, module, cross-checks
# ============================================================================

def owning_module(rust_name):
    """The lib.rs module an item is visible under, or None."""
    if rust_name.startswith(EXCLUDED_PREFIXES):
        return None
    for prefix, module in REEXPORTS.items():
        if rust_name.startswith(prefix):
            return module
    parts = rust_name.split("::")
    if len(parts) < 2 or parts[0] != CRATE:
        return None
    return parts[1] if parts[1] in PUB_MODULES else None


def self_type(rust_name):
    """Last path segment of the impl's self type; None for a free item."""
    if "{" not in rust_name:
        return None
    m = (SELF_TYPE_TRAIT_RE.search(rust_name)
         if TRAIT_IMPL_RE.search(rust_name)
         else SELF_TYPE_INHERENT_RE.search(rust_name))
    return m.group(1).split("::")[-1] if m else None


def load_pub_types():
    for root in RUST_SRC_ROOTS:
        types = set()
        for rel in PUB_MODULE_FILES:
            try:
                with open(os.path.join(root, rel)) as fh:
                    types.update(PUB_TYPE_RE.findall(fh.read()))
            except OSError:
                pass
        if types:
            return types
    return set()


def is_pub_module(entry, pub_types):
    module = owning_module(entry["rust_name"])
    st = self_type(entry["rust_name"])
    return bool(module and (st is None or st in pub_types))


def rust_visibility(entry):
    """Visibility keyword on the `fn` line of the entry's source range."""
    a, b = (int(x[1:]) for x in entry["lines"].split("-"))
    with open(os.path.join(REPO, entry["source"])) as fh:
        # ranges may start at the body; look a few lines above for the `fn` line
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
    """Hand-written Lean files mentioning `lean_name` or its instance record."""
    short = lean_name[len(LEAN_NS):] if lean_name.startswith(LEAN_NS) else lean_name
    targets = {short}
    if ".Insts." in short:
        targets.add(short.rsplit(".", 1)[0])
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


# ============================================================================
# output
# ============================================================================

def compute_top(rows, pub_types):
    callers = build_callers(rows)
    candidates = [r for r in rows if not is_record(r) and not is_loop(r)]
    top = []
    for r in candidates:
        if callers[r["lean_name"]]:
            continue
        cat = categorize(r)
        inherent = cat.startswith("inherent_")
        top.append({
            "lean_name": r["lean_name"],
            "rust_name": r["rust_name"],
            "category": cat,
            "pub_module": is_pub_module(r, pub_types) if inherent else None,
            "specified": r["specified"],
            "verified": r["verified"],
            "verification_status": r["verification_status"],
            "is_hidden": r["is_hidden"],
            "is_ignored": r["is_ignored"],
            "is_extraction_artifact": r["is_extraction_artifact"],
            "source": r["source"],
            "lines": r["lines"],
            "external_lean_refs": external_lean_refs(r["lean_name"]),
            "rust_grep_hits": rust_grep_hits(method_name(r)) if inherent else None,
        })
    top.sort(key=lambda x: (x["category"], x["lean_name"]))
    return candidates, top


def write_outputs(probe, probe_label, rows, candidates, top, dropped_foreign, recovered):
    counts = collections.Counter(x["category"] for x in top)
    out = {
        "method": "probe-lean extract record in Funs.lean (Aeneas def) with no "
                  "dependant among the other records; trait-instance records "
                  "are transparent (transitively), *_loop bodies fold into "
                  "their parent, records and loop bodies are not candidates; "
                  "rust_name / Rust lines from the Aeneas docstring in "
                  "Funs.lean; `.mutual` loop-body calls recovered from the "
                  "Lean source",
        "source": probe_label,
        "probe_tool": probe["tool"],
        "probe_timestamp": probe["timestamp"],
        "probe_commit": probe["source"]["commit"],
        "rows_total": len(rows),
        "foreign_impls_dropped": sorted(dropped_foreign),
        "mutual_loops_recovered": sorted(recovered),
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
    with open(os.path.join(REPO, ".verilib", OUT_STEM + ".json"), "w") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)

    titles = {
        "inherent_pub": "固有方法，`pub`",
        "inherent_pub_crate": "固有方法，`pub(crate)`",
        "inherent_private": "固有方法，私有",
        "trait_impl": "trait 实现方法",
        "operator_forwarder": "运算符转发壳（macros.rs 生成）",
    }
    md = [
        "# graph-top（probe 版）：Funs.lean 中不被其他抽取函数依赖的函数",
        "",
        f"来源: `{probe_label}`（{probe['tool']['name']} {probe['tool']['version']}，"
        f"commit `{probe['source']['commit'][:8]}`；Funs.lean 记录 "
        f"{len(rows) + len(dropped_foreign)} 条，剔除 {len(dropped_foreign)} 条外部类型 impl 记录后 "
        f"{len(rows)} 行；再剔除 {out['records_excluded']} 个 trait 实例记录、"
        f"{out['loop_bodies_excluded']} 个 `_loop` 体后 {len(candidates)} 个候选）；"
        f"共 **{len(top)}** 条。",
        "判定: 候选函数不被任何其他候选函数依赖。实例记录透传（含 supertrait 链），"
        "`P_loop` 的依赖记为 `P` 的依赖。",
        f"probe 对 `partial_fixpoint` 循环体只记录 `<loop>.mutual` 依赖且无该记录，"
        f"{len(recovered)} 个循环体的调用改由扫描 Funs.lean 源码恢复。",
        "`rust_name` 与 Rust 行号取自 Funs.lean 中每个 def 顶部的 Aeneas docstring。",
        "分类只按 Rust 源里 `fn` 行的可见性关键字，不判断是否为 API 入口；`模块` 列 = 所属模块是否由 lib.rs 导出"
        "（`pub` 但模块未导出 = backend 内部函数）。"
        f"`external_lean_refs` = 手写 Lean（{', '.join(f'`{f}`' for f in HAND_WRITTEN_LEAN)}）"
        f"中提到该函数或其实例记录的文件；本次 {out['external_lean_ref_count']} 条非空。"
        "`rust_grep_hits` = crate 非测试源码中 `name(` 的出现次数"
        "（定义行除外），仅作交叉核对提示；按方法名匹配，同名方法会互相污染，高计数不等于有调用者。",
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
    with open(os.path.join(REPO, ".verilib", OUT_STEM + ".md"), "w") as fh:
        fh.write("\n".join(md))
    return out


def diff_against_reference(top):
    if not os.path.exists(REFERENCE):
        return
    with open(REFERENCE) as fh:
        ref = {x["lean_name"]: x for x in json.load(fh)["top_level"]}
    new = {x["lean_name"]: x for x in top}
    both = set(ref) & set(new)
    buckets = [
        ("only-reference", sorted(set(ref) - set(new))),
        ("only-probe", sorted(set(new) - set(ref))),
        ("category-diff", sorted(n for n in both if ref[n]["category"] != new[n]["category"])),
        ("specified-diff", sorted(n for n in both if ref[n]["specified"] != new[n]["specified"])),
    ]
    print(f"vs {os.path.relpath(REFERENCE, REPO)}: {len(ref)} reference / {len(new)} probe; "
          + ", ".join(f"{tag} {len(names)}" for tag, names in buckets))
    for tag, names in buckets:
        for n in names:
            print(f"  {tag}: {n}")


def main():
    probe_path = find_probe()
    probe_label = os.path.relpath(probe_path, REPO)
    probe, rows, dropped_foreign, recovered = load_rows(probe_path)
    print(f"probe {probe_label}: {probe['tool']['name']} {probe['tool']['version']}, "
          f"commit {probe['source']['commit'][:8]}; {len(rows)} rows "
          f"({len(dropped_foreign)} foreign-type impls dropped, "
          f"{len(recovered)} `.mutual` loop bodies recovered from Funs.lean)")
    candidates, top = compute_top(rows, load_pub_types())
    out = write_outputs(probe, probe_label, rows, candidates, top, dropped_foreign, recovered)
    print(f"top-level: {len(top)} / {len(candidates)} candidates ({out['by_category']})")
    diff_against_reference(top)


if __name__ == "__main__":
    main()
