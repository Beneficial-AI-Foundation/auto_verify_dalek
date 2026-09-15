#!/usr/bin/env python3
"""Build the agent-facing bundle: top-level specs only, every proof `sorry`.

The repository keeps the full human reference (internal specs + proofs).
This script derives, into a separate directory, the input an agent receives:

  * code, frozen:      Funs.lean, Types*.lean, Aux.lean, FunsExternal.lean,
                       ExternallyVerified.lean, Tactics.lean, Math/, Utils/
  * top-level specs:   the Specs/ files that functions.json attributes to a
                       row of .verilib/top_level_funs.json (DEC-04 lean-top),
                       with every theorem / lemma / example body replaced by
                       `sorry` and imports of dropped Specs modules removed
  * stubs:             a dropped Specs/ file that a kept file imports
                       (transitively) and that declares vocabulary (def,
                       abbrev, structure, instance, notation, attribute, ...)
                       is kept as a definitions-only stub: every theorem /
                       lemma / example is cut out together with its
                       attributes and docstring.  Statements of kept specs
                       need this vocabulary (e.g. `SQRT_M1_val`).
  * dropped:           every other Specs/ file (internal specs, orphans).
                       An import of a dropped module is replaced by that
                       module's own imports, recursively, so `Funs`,
                       `ExternallyVerified`, `Math.*` still arrive.
  * root module:       Curve25519Dalek.lean rewritten to import what is kept

`.lake/packages` is symlinked (8.5 GB of dependencies); `.lake/build` is
copied so unchanged modules are not rebuilt (Lake traces are content-hashed).

Usage:
  python3 harness/build_without_internal_spec.py            # write bundle
  python3 harness/build_without_internal_spec.py --build    # then `lake build`
  python3 harness/build_without_internal_spec.py --out DIR  # other location
  python3 harness/build_without_internal_spec.py --theorem-level \
      --top-source .verilib/top_level_funs_probe.json --out dalek-top-spec-only
                                          # keep only the top-level spec theorems
                                          # themselves; helper lemmas and specs
                                          # of internal functions in the same
                                          # file are cut like in a stub
  python3 harness/build_without_internal_spec.py --theorem-level --strip-comments ...
                                          # additionally remove all comments
  python3 harness/build_without_internal_spec.py ... \
      --minimize-math .verilib/probes/lean_bundle_Curve25519Dalek_0.1.0.json
                                          # cut every Math/ declaration the
                                          # bundle does not depend on

--strip-comments: remove every comment from the kept Specs/ files and stubs
(module docs `/-! -/`, docstrings `/-- -/`, block comments `/- -/`, line
comments `--`), except the copyright header at the top of the file, whose
`Authors:` line is dropped as well; the generated `-- STUB ...` / `-- generated
...` header line is not written either (the counts are in bundle_manifest.json).  The
human comments carry natural-language specs and proof hints (tactic
workarounds, timeouts) that the agent must not receive.

--minimize-math PROBE: PROBE is a probe-lean extract of a previously built
bundle (same Specs selection!).  Every Math/ declaration that is not in the
dependency closure of the declarations outside Math/ (Specs statements, Aux,
TypesAux, ...) is cut out of its file, together with its docstring,
attributes and `... in` prefixes.  The sorry-assumptions of
harness/frozen/math_assumptions.json are kept (with their statement closure)
even when nothing uses them; --math-keep NAME,... keeps further declarations
(e.g. simp lemmas the probe graph does not record).  --math-closure TSV merges
the exact closure computed by harness/math_closure.lean (run in a built bundle:
`lake env lean ../harness/math_closure.lean > .verilib/math_closure.tsv`); the probe
graph misses the `_proof_N` auxiliaries of definitions, this does not.  A Math
file left without
declarations is dropped and imports of it are replaced by its own imports.
Rerun probe-lean on the result to check the closure; `lake build` is the
final arbiter (implicit uses: simp sets, notation, deriving).

--theorem-level: a kept Specs/ file keeps exactly the theorems that
functions.json attributes to a top-level row (full name = the row's lean_name
minus its last component, i.e. the function's namespace, + the theorem name
from spec_statement).  Every other theorem / lemma / example block is removed.

Default output: <repo parent>/dalek-without-interal-spec
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(os.path.dirname(REPO), "dalek-without-interal-spec")
MARKER = ".dalek-bundle"          # written into the output dir; guards rm -rf
SPECS_DIR = "Curve25519Dalek/Specs"
SPECS_MOD = "Curve25519Dalek.Specs."
COPY_TOP = ["lakefile.toml", "lake-manifest.json", "lean-toolchain", "Utils.lean"]
COPY_DIRS = ["Utils"]
LIB_DIR = "Curve25519Dalek"
MATH_DIR = "Curve25519Dalek/Math"
MATH_MOD = "Curve25519Dalek.Math."
MATH_ASSUMPTIONS = "harness/frozen/math_assumptions.json"

DECL_RE = re.compile(r"^(?:private\s+|protected\s+)?(?:theorem|lemma|example)\b", re.M)
VOCAB_RE = re.compile(
    r"^(?:@\[[^\]]*\]\s*)*(?:private\s+|protected\s+|noncomputable\s+|partial\s+|unsafe\s+)*"
    r"(?:def|abbrev|structure|inductive|class|instance|opaque|axiom|notation|infix|infixl|infixr|"
    r"prefix|postfix|syntax|macro|macro_rules|elab|declare_syntax_cat|register_option|"
    r"initialize|attribute|scoped|local\s+notation|set_option)\b", re.M)
IMPORT_RE = re.compile(r"^import\s+(\S+)\s*$")
OPEN, CLOSE = "([{⦃⟨", ")]}⦄⟩"


def read(rel):
    with open(os.path.join(REPO, rel)) as fh:
        return fh.read()


def imports_of(text):
    return [m.group(1) for m in (IMPORT_RE.match(l) for l in text.split("\n")) if m]


def path_of(mod):
    return mod.replace(".", "/") + ".lean"


def strip_comments(text):
    text = re.sub(r"/-.*?-/", "", text, flags=re.S)
    return re.sub(r"--[^\n]*", "", text)


COPYRIGHT_RE = re.compile(r"\A(/-\s*\nCopyright.*?-/\n)", re.S)


def strip_all_comments(text):
    """Remove every Lean comment (`--` to end of line, nested `/- -/` blocks
    including `/--` docstrings and `/-!` module docs) except a leading
    copyright header (its `Authors:` line dropped); string literals are
    skipped.  Trailing whitespace is
    trimmed and runs of blank lines collapsed to one.  -> (text, removed)"""
    head = ""
    m = COPYRIGHT_RE.match(text)
    if m:
        head = re.sub(r"^Authors?:[^\n]*\n", "", m.group(1), flags=re.M)
        text = text[m.end():]
    out = []
    i, n, removed = 0, len(text), 0
    while i < n:
        if text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            removed += 1
            continue
        if text.startswith("/-", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/-", j):
                    depth += 1
                    j += 2
                elif text.startswith("-/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            i = j
            removed += 1
            continue
        if text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        out.append(text[i])
        i += 1
    body = "".join(out)
    body = "\n".join(l.rstrip() for l in body.split("\n"))
    body = re.sub(r"\n{3,}", "\n\n", body)
    return head + body.lstrip("\n"), removed


def declares_vocab(text):
    body = strip_comments(text)
    body = re.sub(r"^set_option[^\n]*$", "", body, flags=re.M)      # options alone are not vocabulary
    return VOCAB_RE.search(body) is not None


def mod_of(path):
    return path[:-len(".lean")].replace("/", ".")


THM_NAME_RE = re.compile(r"(?:theorem|lemma)\s+([\w.']+)")


def load_top_spec_files(top_source):
    """-> (keep, theorems, unspecified)
    keep:        spec_file -> [lean_name]            (files to keep)
    theorems:    spec_file -> {full theorem name}     (for --theorem-level)
    unspecified: [lean_name] top-level rows without a spec_file"""
    with open(os.path.join(REPO, "functions.json")) as fh:
        rows = json.load(fh)["functions"]
    with open(os.path.join(REPO, top_source)) as fh:
        top = {r["lean_name"] for r in json.load(fh)["top_level"]}
    keep, theorems, unspecified = {}, {}, []
    for r in rows:
        if r["lean_name"] not in top:
            continue
        if not r.get("spec_file"):
            unspecified.append(r["lean_name"])
            continue
        keep.setdefault(r["spec_file"], []).append(r["lean_name"])
        m = THM_NAME_RE.search(r.get("spec_statement") or "")
        if not m:
            sys.exit(f"no theorem name in spec_statement of {r['lean_name']}")
        ns = r["lean_name"].rsplit(".", 1)[0]
        theorems.setdefault(r["spec_file"], set()).add(f"{ns}.{m.group(1)}")
    return keep, theorems, sorted(unspecified)


def find_proof_start(text, pos):
    """Index of the top-level `:=` that starts the body of the decl at `pos`."""
    depth = 0
    i = pos
    n = len(text)
    while i < n:
        c = text[i]
        if text.startswith("--", i):
            i = text.find("\n", i)
            if i < 0:
                return -1
            continue
        if text.startswith("/-", i):
            j = text.find("-/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
        elif depth == 0 and text.startswith(":=", i):
            return i
        i += 1
    return -1


def find_proof_end(text, pos):
    """Index of the first column-0 non-blank line after `pos` (or EOF)."""
    i = text.find("\n", pos)
    while i >= 0:
        j = i + 1
        if j >= len(text):
            return len(text)
        if text[j] not in " \t\n\r":
            return j
        i = text.find("\n", j)
    return len(text)


def decl_block_start(text, pos):
    """Back up from the `theorem` line over its attributes, docstring and
    `... in` prefixes so the whole block can be removed."""
    lines = text[:pos].split("\n")
    # lines[-1] is the (empty) prefix of the theorem line itself
    k = len(lines) - 1
    while k > 0:
        prev = lines[k - 1].rstrip()
        st = re.sub(r"(?<![/-])--.*$", "", prev).strip()  # ignore trailing `--` comment, not `/--`
        if st == "" and prev.strip().startswith("--"):     # a pure `--` comment line
            k -= 1
            continue
        if st.startswith("@[") or st.endswith(" in") or st == "in":
            k -= 1
            continue
        if st.endswith("-/"):
            # docstring or comment block directly above: find its opening line
            j = k - 1
            while j >= 0 and not lines[j].lstrip().startswith(("/--", "/-")):
                j -= 1
            if j >= 0:
                k = j
                continue
        break
    return len("\n".join(lines[:k])) + (1 if k > 0 else 0)


NAME_RE = re.compile(r"(?:private\s+|protected\s+)?(?:theorem|lemma)\s+([\w.']+)")
ATTR_LINE_RE = re.compile(r"^(\s*attribute\s+\[[^\]]*\]\s+)(.+?)\s*$")


NS_RE = re.compile(r"^(namespace|section|end)(?:[ \t]+(\S+))?[ \t]*$", re.M)


def namespace_at(text, pos):
    """Dotted namespace open at `pos` (tracks `namespace`/`section`/`end`)."""
    stack = []
    for m in NS_RE.finditer(text, 0, pos):
        kw, name = m.group(1), m.group(2)
        if kw == "namespace":
            stack.append(("ns", name))
        elif kw == "section":
            stack.append(("sec", name))
        elif stack:
            stack.pop()
    return ".".join(n for k, n in stack if k == "ns")


def filter_theorems(text, keep=None):
    """keep=None: cut every theorem/lemma/example block (with attributes +
    docstring).  keep=set of full names: cut every block whose full name
    (namespace + declared name) is not in `keep`; a kept block gets its
    proof replaced by `sorry`.  Afterwards drop `attribute [...] name`
    references to the cut theorems.  -> (text, removed, kept, kept_names)"""
    out = []
    i = 0
    removed = set()
    count = 0
    kept = []
    while True:
        m = DECL_RE.search(text, i)
        if not m:
            out.append(text[i:])
            break
        start = find_proof_start(text, m.end())
        if start < 0:
            out.append(text[i:])
            break
        nm = NAME_RE.match(text, m.start())
        full = None
        if nm:
            name = nm.group(1)
            if name.startswith("_root_."):
                full = name[len("_root_."):]
            else:
                ns = namespace_at(text, m.start())
                full = f"{ns}.{name}" if ns else name
        end = find_proof_end(text, start)
        if keep is not None and full in keep:
            out.append(text[i:start])
            out.append(":= by\n  sorry\n\n")
            kept.append(full)
            i = end
            continue
        if nm:
            removed.add(nm.group(1))
            removed.add(nm.group(1).split(".")[-1])
        block_start = decl_block_start(text, m.start())
        out.append(text[i:block_start])
        count += 1
        i = end
    lines = []
    for line in "".join(out).split("\n"):
        am = ATTR_LINE_RE.match(line)
        if am:
            names = [n for n in am.group(2).split()
                     if n not in removed and n.split(".")[-1] not in removed]
            if not names:
                continue
            line = am.group(1) + " ".join(names)
        lines.append(line)
    return "\n".join(lines), count, len(kept), kept


def remove_theorems(text):
    new, n, _, _ = filter_theorems(text)
    return new, n


def sorry_proofs(text):
    out = []
    i = 0
    count = 0
    while True:
        m = DECL_RE.search(text, i)
        if not m:
            out.append(text[i:])
            break
        start = find_proof_start(text, m.end())
        if start < 0:
            out.append(text[i:])
            break
        end = find_proof_end(text, start)
        out.append(text[i:start])
        out.append(":= by\n  sorry\n\n")
        count += 1
        i = end
    return "".join(out), count


class MathMin:
    """Minimal Math/ subset from a probe-lean extract of the bundle.

    keep:     probe id -> record, the Math declarations to keep
    removed:  file -> [display names cut]
    dropped_mods: Math modules left without any declaration"""

    def __init__(self, probe_path, extra_names=(), closure_tsv=None):
        with open(os.path.join(REPO, probe_path)) as fh:
            self.data = json.load(fh)["data"]
        d = self.data
        self.unmapped = []
        if closure_tsv:                        # exact closure from harness/math_closure.lean
            extra_names = list(extra_names) + self.map_lean_names(closure_tsv)
        path = lambda v: v.get("code-path") or ""
        self.math = {k for k, v in d.items() if path(v).startswith(MATH_DIR + "/")}
        roots = [k for k, v in d.items()
                 if v.get("is-in-package") and path(v) and k not in self.math]
        with open(os.path.join(REPO, MATH_ASSUMPTIONS)) as fh:
            assumptions = [a["name"] for a in json.load(fh)["assumptions"]]
        for name in list(assumptions) + list(extra_names):
            # kernel-level `foo._proof_N` obligations are recorded under `foo` by the probe
            name = re.sub(r"\._proof_\d+$", "", name)
            pid = "probe:" + name
            if pid not in d:
                sys.exit(f"--minimize-math: {name} not in probe {probe_path}")
            roots.append(pid)
        seen = set(roots)
        stack = list(roots)
        while stack:
            k = stack.pop()
            for x in d[k]["dependencies"]:
                if x in d and x not in seen:
                    seen.add(x)
                    stack.append(x)
        self.keep = {k for k in seen if k in self.math}
        self.by_file = {}
        for k in self.math:
            self.by_file.setdefault(path(d[k]), []).append(k)
        self.dropped_mods = {mod_of(f) for f, ks in self.by_file.items()
                             if not any(k in self.keep for k in ks)}
        self.removed = {}
        self._imports = {}
        # namespaces that exist only in dropped modules: `open X` of them must go
        ns = lambda text: {m.group(2) for m in NS_RE.finditer(text) if m.group(1) == "namespace" and m.group(2)}
        dropped_ns = set()
        for mod in self.dropped_mods:
            dropped_ns |= ns(read(path_of(mod)))
        for r, _, fs in os.walk(os.path.join(REPO, LIB_DIR)):
            for f in fs:
                rel = os.path.relpath(os.path.join(r, f), REPO)
                if f.endswith(".lean") and mod_of(rel) not in self.dropped_mods:
                    dropped_ns -= ns(read(rel))
        self.dropped_ns = dropped_ns

    def rewrite_opens(self, text):
        """Drop names of vanished namespaces from `open ...` lines."""
        if not self.dropped_ns:
            return text
        out = []
        for line in text.split("\n"):
            m = re.match(r"^(\s*open(?:\s+scoped)?\s+)(.+?)(\s+in)?\s*$", line)
            if m:
                names = [n for n in m.group(2).split() if n not in self.dropped_ns]
                if not names:
                    continue
                line = m.group(1) + " ".join(names) + (m.group(3) or "")
            out.append(line)
        return "\n".join(out)

    def map_lean_names(self, tsv):
        """Lean constant names (harness/math_closure.lean output) -> probe names.
        `_private.<Mod>.0.` prefixes are dropped; auxiliaries (`foo._proof_3`,
        `Point.mk`, `Point.rec`, `foo.match_1`, `foo.eq_1`, ...) are mapped to the
        longest prefix the probe knows."""
        names = []
        for line in open(os.path.join(REPO, tsv)):
            name = line.split("\t")[0].strip()
            if not name:
                continue
            name = re.sub(r"^_private\.[\w.]+?\.\d+\.", "", name)
            parts = name.split(".")
            # `X.match_N` matchers are shared between definitions: reaching one does
            # not mean X is needed (X shows up on its own line if it is)
            if any(re.fullmatch(r"match_\d+", q) for q in parts):
                continue
            while parts and "probe:" + ".".join(parts) not in self.data:
                parts.pop()
            if parts:
                names.append(".".join(parts))
            else:
                self.unmapped.append(name)
        return names

    def imports_of_mod(self, mod):
        if mod not in self._imports:
            self._imports[mod] = imports_of(read(path_of(mod)))
        return self._imports[mod]

    def rewrite(self, rel, text):
        """Cut every non-kept declaration of Math file `rel`."""
        d = self.data
        lines = text.split("\n")
        # line ranges shared by several (auto-generated) declarations: keep if any is kept
        ranges = {}
        for k in self.by_file[rel]:
            rg = (d[k]["code-text"]["lines-start"], d[k]["code-text"]["lines-end"])
            ranges.setdefault(rg, []).append(k)
        cut = []                                  # (start_line, end_line) 1-based inclusive
        names = []
        for (a, b), ks in sorted(ranges.items()):
            if any(k in self.keep for k in ks):
                continue
            off = len("\n".join(lines[:a - 1])) + (1 if a > 1 else 0)
            start = text.count("\n", 0, decl_block_start(text, off)) + 1
            cut.append((start, b))
            names += [d[k]["display-name"] for k in ks]
        removed_names = set()
        for k in self.by_file[rel]:
            if k not in self.keep:
                nm = k[len("probe:"):]
                removed_names.add(nm)
                removed_names.add(nm.split(".")[-1])
        gone = set()
        for a, b in cut:
            gone.update(range(a, b + 1))
        out = []
        for i, line in enumerate(lines, 1):
            if i in gone:
                continue
            am = ATTR_LINE_RE.match(line)
            if am:
                keep_n = [n for n in am.group(2).split()
                          if n not in removed_names and n.split(".")[-1] not in removed_names]
                if not keep_n:
                    continue
                line = am.group(1) + " ".join(keep_n)
            out.append(line)
        new = "\n".join(out)
        new = re.sub(r"\n{3,}", "\n\n", new)
        self.removed[rel] = sorted(names)
        return new


class Closure:
    """Decide, for every Specs module reachable from the kept files, whether
    it is kept (top spec), stubbed (vocabulary only) or dropped."""

    def __init__(self, kept_mods, mathmin=None):
        self.kept = set(kept_mods)
        self.stub = set()
        self.dropped = set()
        self._resolved = {}
        self.mathmin = mathmin

    def resolve_import(self, mod):
        """Modules to import instead of `mod` (a list; `mod` itself if kept/stub)."""
        if self.mathmin and mod in self.mathmin.dropped_mods:
            if mod not in self._resolved:
                self._resolved[mod] = []
                res = []
                for imp in self.mathmin.imports_of_mod(mod):
                    for r in self.resolve_import(imp):
                        if r not in res:
                            res.append(r)
                self._resolved[mod] = res
            return self._resolved[mod]
        if not mod.startswith(SPECS_MOD) or mod in self.kept:
            return [mod]
        if mod in self._resolved:
            return self._resolved[mod]
        self._resolved[mod] = []                       # cycle guard
        text = read(path_of(mod))
        if declares_vocab(text):
            self.stub.add(mod)
            res = [mod]
        else:
            self.dropped.add(mod)
            res = []
            for imp in imports_of(text):
                for r in self.resolve_import(imp):
                    if r not in res:
                        res.append(r)
        self._resolved[mod] = res
        return res

    def rewrite_imports(self, text):
        lines, changed = [], []
        seen = set()
        if self.mathmin:
            text = self.mathmin.rewrite_opens(text)
        for line in text.split("\n"):
            m = IMPORT_RE.match(line)
            if not m:
                lines.append(line)
                continue
            repl = self.resolve_import(m.group(1))
            if repl != [m.group(1)]:
                changed.append({"import": m.group(1), "replaced_by": repl})
            for r in repl:
                if r not in seen:
                    seen.add(r)
                    lines.append(f"import {r}")
        return "\n".join(lines), changed


def rewrite_spec(text, closure, strip=False):
    """Kept top spec: fix imports, sorry every proof."""
    text, changed = closure.rewrite_imports(text)
    text, n = sorry_proofs(text)
    if strip:
        text, _ = strip_all_comments(text)
    return text, n, changed


def rewrite_spec_theorem_level(text, closure, keep_names, strip=False):
    """Kept top spec, theorem level: fix imports, keep only the whitelisted
    theorems (proof -> sorry), cut every other theorem / lemma / example."""
    text, changed = closure.rewrite_imports(text)
    text, cut, n, kept = filter_theorems(text, keep_names)
    header = "-- generated by harness/build_without_internal_spec.py --theorem-level: " \
             f"{n} top-level spec(s) kept (proof -> sorry), {cut} other theorem block(s) removed.\n"
    if strip:                       # no generated header either: only copyright/license stay
        text, _ = strip_all_comments(text)
        header = ""
    return header + text, n, cut, kept, changed


def rewrite_stub(text, closure, strip=False):
    """Vocabulary stub: fix imports, cut every theorem block."""
    text, changed = closure.rewrite_imports(text)
    text, n = remove_theorems(text)
    header = "-- STUB generated by harness/build_without_internal_spec.py: definitions only, " \
             f"{n} theorem block(s) removed.\n"
    if strip:
        text, _ = strip_all_comments(text)
        header = ""
    return header + text, n, changed


def rewrite_root(text, keep_mods, dropped_math=()):
    lines = []
    for line in text.split("\n"):
        m = IMPORT_RE.match(line)
        if m and m.group(1).startswith(SPECS_MOD) and m.group(1) not in keep_mods:
            continue
        if m and m.group(1) in dropped_math:
            continue
        lines.append(line)
    return "\n".join(lines)


def reset_out(out):
    if os.path.exists(out):
        if not os.path.exists(os.path.join(out, MARKER)):
            sys.exit(f"refusing to remove {out}: no {MARKER} marker (not a bundle dir)")
        shutil.rmtree(out)
    os.makedirs(out)
    with open(os.path.join(out, MARKER), "w") as fh:
        fh.write("generated by harness/build_without_internal_spec.py\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--build", action="store_true", help="run `lake build` afterwards")
    ap.add_argument("--no-build-cache", action="store_true",
                    help="do not copy .lake/build (full rebuild)")
    ap.add_argument("--top-source", default=".verilib/top_level_funs.json",
                    help="JSON with a `top_level` list of {lean_name} rows (repo-relative)")
    ap.add_argument("--theorem-level", action="store_true",
                    help="keep only the top-level spec theorems inside a kept Specs file; "
                         "cut helper lemmas and specs of internal functions")
    ap.add_argument("--minimize-math", metavar="PROBE",
                    help="probe-lean extract of a built bundle (repo-relative); cut every Math/ "
                         "declaration outside the dependency closure of the non-Math declarations")
    ap.add_argument("--math-closure", metavar="TSV",
                    help="output of `lake env lean harness/math_closure.lean` run in a built bundle "
                         "(repo-relative); exact closure, merged into the probe closure")
    ap.add_argument("--math-keep", default="",
                    help="comma-separated Math declaration names to keep in addition (--minimize-math)")
    ap.add_argument("--strip-comments", action="store_true",
                    help="remove all comments (module docs, docstrings, `--`) from kept Specs "
                         "files and stubs, except the copyright header")
    args = ap.parse_args()
    out = os.path.abspath(args.out)

    keep, theorems, unspecified = load_top_spec_files(args.top_source)
    kept_mods = {mod_of(p) for p in keep}
    all_specs = sorted(
        os.path.relpath(os.path.join(r, f), REPO)
        for r, _, fs in os.walk(os.path.join(REPO, SPECS_DIR)) for f in fs if f.endswith(".lean"))
    dropped_specs = [p for p in all_specs if p not in keep]
    missing = [p for p in keep if p not in all_specs]
    if missing:
        sys.exit(f"functions.json names spec files that do not exist: {missing}")

    reset_out(out)
    for f in COPY_TOP:
        shutil.copy2(os.path.join(REPO, f), os.path.join(out, f))
    for d in COPY_DIRS:
        shutil.copytree(os.path.join(REPO, d), os.path.join(out, d))
    shutil.copytree(os.path.join(REPO, LIB_DIR), os.path.join(out, LIB_DIR),
                    ignore=lambda d, names: [n for n in names
                                             if os.path.join(d, n) == os.path.join(REPO, SPECS_DIR)])

    mathmin = None
    if args.minimize_math:
        extra = [n for n in args.math_keep.split(",") if n]
        mathmin = MathMin(args.minimize_math, extra, args.math_closure)
        if mathmin.unmapped:
            print(f"  warning: {len(mathmin.unmapped)} closure constant(s) not mapped to a probe "
                  f"declaration: {mathmin.unmapped[:5]}", file=sys.stderr)
        for rel in sorted(mathmin.by_file):
            dst = os.path.join(out, rel)
            if mod_of(rel) in mathmin.dropped_mods:
                os.remove(dst)
                mathmin.removed[rel] = sorted(mathmin.data[k]["display-name"]
                                              for k in mathmin.by_file[rel])
                continue
            new = mathmin.rewrite(rel, read(rel))
            if args.strip_comments:
                new, _ = strip_all_comments(new)
            with open(dst, "w") as fh:
                fh.write(new)
        # imports between Math files / from Aux of a dropped module
        for rel in sorted(mathmin.by_file):
            if mod_of(rel) in mathmin.dropped_mods:
                continue
            dst = os.path.join(out, rel)
            with open(dst) as fh:
                txt = fh.read()
            txt2, _ = Closure(set(), mathmin).rewrite_imports(txt)
            if txt2 != txt:
                with open(dst, "w") as fh:
                    fh.write(txt2)

    closure = Closure(kept_mods, mathmin)
    sorried = {}
    cut_from_specs = {}
    kept_theorems = {}
    import_changes = {}
    for rel in sorted(keep):
        if args.theorem_level:
            new, n, cut, kept_names, changed = rewrite_spec_theorem_level(
                read(rel), closure, theorems[rel], args.strip_comments)
            cut_from_specs[rel] = cut
            kept_theorems[rel] = sorted(kept_names)
            missing_thms = theorems[rel] - set(kept_names)
            if missing_thms:
                sys.exit(f"{rel}: top-level spec theorem(s) not found: {sorted(missing_thms)}")
        else:
            new, n, changed = rewrite_spec(read(rel), closure, args.strip_comments)
        sorried[rel] = n
        if changed:
            import_changes[rel] = changed
        dst = os.path.join(out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w") as fh:
            fh.write(new)

    # stubs may pull in further stubs; iterate to a fixpoint
    stubbed = {}
    done = set()
    while closure.stub - done:
        for mod in sorted(closure.stub - done):
            done.add(mod)
            rel = path_of(mod)
            new, n, changed = rewrite_stub(read(rel), closure, args.strip_comments)
            stubbed[rel] = n
            if changed:
                import_changes[rel] = changed
            dst = os.path.join(out, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as fh:
                fh.write(new)

    root = read("Curve25519Dalek.lean")
    with open(os.path.join(out, "Curve25519Dalek.lean"), "w") as fh:
        fh.write(rewrite_root(root, kept_mods | closure.stub,
                              mathmin.dropped_mods if mathmin else ()))
    dropped_specs = [p for p in all_specs if p not in keep and mod_of(p) not in closure.stub]

    os.makedirs(os.path.join(out, ".lake"))
    os.symlink(os.path.join(REPO, ".lake", "packages"), os.path.join(out, ".lake", "packages"))
    if not args.no_build_cache and os.path.isdir(os.path.join(REPO, ".lake", "build")):
        shutil.copytree(os.path.join(REPO, ".lake", "build"), os.path.join(out, ".lake", "build"),
                        symlinks=True)

    manifest = {
        "source_repo": REPO,
        "top_level_source": args.top_source,
        "theorem_level": args.theorem_level,
        "strip_comments": args.strip_comments,
        "kept_spec_files": {p: sorted(v) for p, v in sorted(keep.items())},
        "kept_count": len(keep),
        "stub_spec_files": stubbed,
        "stub_count": len(stubbed),
        "dropped_spec_files": dropped_specs,
        "dropped_count": len(dropped_specs),
        "proofs_replaced_by_sorry": sorried,
        "proofs_replaced_total": sum(sorried.values()),
        "import_rewrites": import_changes,
        "unspecified_top_level": unspecified,
        "unspecified_top_level_count": len(unspecified),
    }
    if mathmin:
        manifest["math_minimized"] = {
            "probe": args.minimize_math,
            "closure_tsv": args.math_closure,
            "unmapped_closure_constants": mathmin.unmapped,
            "extra_keep": [n for n in args.math_keep.split(",") if n],
            "math_total": len(mathmin.math),
            "math_kept": len(mathmin.keep),
            "dropped_modules": sorted(mathmin.dropped_mods),
            "kept_declarations": {
                f: sorted(k[len("probe:"):] for k in ks if k in mathmin.keep)
                for f, ks in sorted(mathmin.by_file.items())},
            "removed_declarations": mathmin.removed,
        }
    if args.theorem_level:
        manifest["kept_theorems"] = kept_theorems
        manifest["kept_theorem_count"] = sum(len(v) for v in kept_theorems.values())
        manifest["theorems_cut_from_kept_files"] = cut_from_specs
    with open(os.path.join(out, "bundle_manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)

    print(f"bundle: {out}")
    print(f"  specs kept {len(keep)}, stubs {len(stubbed)}, dropped {len(dropped_specs)}, "
          f"proofs -> sorry {manifest['proofs_replaced_total']}, "
          f"theorems cut from stubs {sum(stubbed.values())}, "
          f"theorems cut from kept files {sum(cut_from_specs.values())}, "
          f"top-level rows without spec {len(unspecified)}")
    if mathmin:
        print(f"  Math: kept {len(mathmin.keep)}/{len(mathmin.math)} declarations, "
              f"dropped modules {sorted(m[len(MATH_MOD):] for m in mathmin.dropped_mods)}")

    if args.build:
        r = subprocess.run(["lake", "build"], cwd=out)
        sys.exit(r.returncode)


if __name__ == "__main__":
    main()
