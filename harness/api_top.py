#!/usr/bin/env python3
"""Build the api-top catalog: the user-facing pub API surface of curve25519-dalek,
intersected with what this benchmark actually extracted and specified.

Judgement (DEC-04 follow-up):
  graph-top (.verilib/top_level_specs.json)  = maximal elements of the spec call
    graph -> anchoring/audit instrument only.
  api-top (this script)                      = deletion list for the Phase-2
    spec-budget experiments. A spec belongs here iff its target function is part
    of the crate's user-facing API surface, regardless of internal callers.

Each api-top row carries `caller_anchored`: true iff some OTHER spec'd function
(directly or transitively through spec-less helpers) calls the target. Those
rows are a distinct experimental condition when deleted: an agent can satisfy
the internal caller with a spec weaker than the user-facing contract and still
go green, so grading must rely on synth_eq_human, not on the build.

Inputs (all pinned):
  functions.json                                (extraction inventory, repo root)
  .verilib/probes/lean_Curve25519Dalek_0.1.0.json  (dependency probe)
  ~/curve25519-dalek-lean-verify/curve25519-dalek/src/  (Rust source, for `pub`)

Outputs:
  .verilib/api_top_specs.json
  .verilib/api_top_specs.md
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST_SRC_ROOT = os.path.expanduser("~/curve25519-dalek-lean-verify")

API_MODULES = {
    "curve25519-dalek/src/edwards.rs",
    "curve25519-dalek/src/edwards/affine.rs",
    "curve25519-dalek/src/ristretto.rs",
    "curve25519-dalek/src/montgomery.rs",
    "curve25519-dalek/src/scalar.rs",
    "curve25519-dalek/src/constants.rs",
}

# CryptoProver's scouted genuine-API list (spec_gen_experiment_design.md, the
# named examples only -- the doc elides with "..."), used as a cross-check.
CRYPTOPROVER_NAMED = {
    "edwards": ["decompress", "compress", "to_montgomery", "mul_base",
                "mul_clamped", "mul_by_cofactor", "is_small_order",
                "is_torsion_free", "vartime_double_scalar_mul_basepoint"],
    "ristretto": ["decompress", "compress", "from_uniform_bytes",
                  "hash_from_bytes", "from_hash", "double_and_compress_batch",
                  "random", "mul_base", "basepoint"],
    "montgomery": ["to_edwards", "as_affine", "mul_base", "mul_clamped",
                   "mul_bits_be"],
    "scalar": ["from_bytes_mod_order", "from_bytes_mod_order_wide",
               "from_canonical_bytes", "invert", "batch_invert", "random",
               "hash_from_bytes", "from_hash"],
}

TRAIT_IMPL_RE = re.compile(r"\{.+ for .+\}")


def load_probe():
    path = os.path.join(REPO, ".verilib", "probes",
                        "lean_Curve25519Dalek_0.1.0.json")
    with open(path) as fh:
        probe = json.load(fh)["data"]
    strip = lambda s: s.split(":", 1)[1] if ":" in s else s
    kinds, deps = {}, {}
    for k, v in probe.items():
        name = strip(k)
        kinds[name] = v.get("kind")
        deps[name] = [strip(d) for d in v.get("dependencies") or []]
    return kinds, deps


def spec_map(kinds):
    """spec theorem name -> target function name (by the *_spec convention)."""
    return {n: n[:-5] for n in kinds
            if n.endswith("_spec") and kinds[n] == "theorem"}


def caller_anchored_set(kinds, deps, specd_fns):
    """Functions reachable (as callee) from some spec'd function through
    spec-less defs -- the graph-top demotion rule, reused as a label."""
    rev = {}
    for n, ds in deps.items():
        if kinds.get(n) not in ("def", "definition", "opaque"):
            continue
        for d in ds:
            rev.setdefault(d, set()).add(n)
    anchored = set()
    for fn in specd_fns:
        frontier, seen = list(rev.get(fn, ())), set()
        while frontier:
            c = frontier.pop()
            if c in seen:
                continue
            seen.add(c)
            if c in specd_fns and c != fn:
                anchored.add(fn)
                break
            frontier.extend(rev.get(c, ()))
    return anchored


def visibility(entry):
    """Read the Rust source lines behind a functions.json entry."""
    m = re.match(r"L(\d+)-L(\d+)", entry["lines"] or "")
    if not m:
        return "unknown"
    path = os.path.join(RUST_SRC_ROOT, entry["source"])
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except OSError:
        return "unknown"
    lo = max(0, int(m.group(1)) - 3)          # signature may start a bit above
    hi = min(len(lines), int(m.group(2)))
    window = "".join(lines[lo:hi])
    if re.search(r"^\s*pub\s*\((crate|super)\)\s+(const\s+)?fn", window, re.M):
        return "pub(crate)"
    if re.search(r"^\s*pub\s+(const\s+)?fn", window, re.M):
        return "pub"
    if re.search(r"^\s*pub\s+(static|const)\b", window, re.M):
        return "pub-const"
    if re.search(r"^\s*(const\s+)?fn", window, re.M):
        return "private"
    return "unknown"


def main():
    with open(os.path.join(REPO, "functions.json")) as fh:
        functions = json.load(fh)["functions"]
    kinds, deps = load_probe()
    s2f = spec_map(kinds)
    f2s = {v: k for k, v in s2f.items()}
    specd_fns = set(s2f.values())
    anchored = caller_anchored_set(kinds, deps, specd_fns)

    # one entry per lean_name, preferring the specified twin
    by_name = {}
    for e in functions:
        if e["source"] not in API_MODULES:
            continue
        # NOTE: is_ignored is a verilib display flag, NOT an exclusion --
        # mul_clamped / is_torsion_free are specified APIs with is_ignored=true.
        if e["is_extraction_artifact"]:
            continue
        cur = by_name.get(e["lean_name"])
        if cur is None or (e["specified"] and not cur["specified"]):
            by_name[e["lean_name"]] = e

    rows, unspecced = [], []
    for e in by_name.values():
        is_trait = bool(TRAIT_IMPL_RE.search(e["rust_name"]))
        vis = visibility(e)
        public = is_trait or vis in ("pub", "pub-const")
        if not public:
            continue
        row = {
            "rust_name": e["rust_name"],
            "lean_name": e["lean_name"],
            "source": f"{e['source']}:{e['lines']}",
            "category": "trait-instance" if is_trait else
                        ("const" if vis == "pub-const" else "api"),
            "visibility": vis if not is_trait else f"trait ({vis})",
            "spec": f2s.get(e["lean_name"]),
            "spec_file": e["spec_file"],
            "caller_anchored": e["lean_name"] in anchored,
        }
        if e["specified"] and row["spec"] is None:
            row["spec"] = "UNMAPPED (specified=true but no *_spec match)"
        if e["specified"] or row["spec"]:
            rows.append(row)
        else:
            unspecced.append(row)

    rows.sort(key=lambda r: (r["category"], r["lean_name"]))
    # drop trait-instance container defs whose method already carries the spec
    # (e.g. `...NegRistrettoPoint` when `...NegRistrettoPoint.neg` is in rows)
    row_names = {r["lean_name"] for r in rows}
    unspecced = [r for r in unspecced
                 if not any(n.startswith(r["lean_name"] + ".")
                            for n in row_names)
                 and ".mutual" not in r["lean_name"]
                 and ".closure." not in r["lean_name"]]
    unspecced.sort(key=lambda r: r["lean_name"])

    # cross-check against CryptoProver's named list
    lean_names = {r["lean_name"].lower() for r in rows}
    unspec_names = {r["lean_name"].lower() for r in unspecced}
    crosscheck = []
    for module, names in CRYPTOPROVER_NAMED.items():
        for n in names:
            probe_hit = any(f".{module}." in ln and ln.endswith("." + n)
                            for ln in lean_names)
            unspec_hit = any(f".{module}." in ln and ln.endswith("." + n)
                             for ln in unspec_names)
            status = ("in api-top" if probe_hit else
                      "extracted, NO SPEC" if unspec_hit else
                      "not extracted")
            crosscheck.append({"module": module, "fn": n, "status": status})

    out = {
        "method": ("user-facing pub API surface (pub fn / pub const / trait "
                   "impl in the five API modules) intersected with the "
                   "extracted+specified set; caller_anchored = some other "
                   "spec'd function reaches it as callee through spec-less "
                   "helpers"),
        "api_modules": sorted(API_MODULES),
        "rust_source_root": RUST_SRC_ROOT,
        "count": len(rows),
        "api_top": rows,
        "extracted_public_but_unspecified": unspecced,
        "cryptoprover_crosscheck": crosscheck,
    }
    with open(os.path.join(REPO, ".verilib", "api_top_specs.json"), "w") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)

    md = ["# api-top：面向用户的 pub API 面 ∩ 已抽取已 spec 集合", "",
          f"来源: `functions.json` + Rust 源码可见性 + probe 调用图；共 **{len(rows)}** 条。",
          "`caller_anchored = yes` 表示存在其他带 spec 的函数（经无 spec helper 传递）调用它——",
          "删除这类 spec 时全绿不等于合格，必须靠 `synth_eq_human` 评分。", ""]
    for cat, title in [("api", "公开 API 函数"), ("const", "公开常量"),
                       ("trait-instance", "Trait 实例")]:
        sub = [r for r in rows if r["category"] == cat]
        if not sub:
            continue
        md += [f"## {title}（{len(sub)} 条）", "",
               "| Lean 名 | spec | caller_anchored | 位置 |", "|---|---|---|---|"]
        for r in sub:
            md.append(f"| `{r['lean_name']}` | {'✓' if r['spec'] else '—'} | "
                      f"{'yes' if r['caller_anchored'] else 'no'} | {r['source']} |")
        md.append("")
    if unspecced:
        md += [f"## 已抽取但无 spec 的公开函数（{len(unspecced)} 条）", ""]
        md += [f"- `{r['lean_name']}` ({r['source']})" for r in unspecced]
        md.append("")
    md += ["## CryptoProver 清单交叉核对", "",
           "| 模块 | 函数 | 状态 |", "|---|---|---|"]
    for c in crosscheck:
        md.append(f"| {c['module']} | `{c['fn']}` | {c['status']} |")
    md.append("")
    with open(os.path.join(REPO, ".verilib", "api_top_specs.md"), "w") as fh:
        fh.write("\n".join(md))

    print(f"api-top: {len(rows)} rows "
          f"({sum(1 for r in rows if r['category']=='api')} api, "
          f"{sum(1 for r in rows if r['category']=='trait-instance')} trait, "
          f"{sum(1 for r in rows if r['category']=='const')} const); "
          f"caller_anchored: {sum(1 for r in rows if r['caller_anchored'])}; "
          f"public-unspecced: {len(unspecced)}")


if __name__ == "__main__":
    sys.exit(main())
