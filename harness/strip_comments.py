#!/usr/bin/env python3
"""Comment stripping for sealed slots (anti-leak), and the inverse merge-back.

Why. Every target file carries natural-language spec sketches, proof outlines
and `Source:` pointers in comments (`/-! … -/`, `/-- … -/`, `/- … -/`, `--`).
They are hints the agent should not get when we measure proof synthesis, the
same way CryptoProver's `strip_specs.py --strip-docs` removes the `///` doc
comments from the peeled Rust surface. This module removes *every* comment
from the Lean files the agent sees, while the operator's checkout keeps them.

Design.

  * Line-preserving. A comment is replaced by nothing but its newlines, so a
    stripped file has exactly the lines of the original, comment text blanked.
    Inventory `path:line:col` entries, `resolve_target`, the prompt's "near
    line N" and the ledger stay valid unchanged. Trailing whitespace left by a
    removed comment is trimmed.

  * Lexer-accurate. Strings (`"…"`, `s!"…"`, raw `r#"…"#`), char literals
    (`'a'`, `'\\n'`, distinguished from primes in `x'`) and `«…»` names are
    skipped, so `--` or `/-` inside them is not a comment. Block comments nest
    as in Lean 4.

  * Reversible merge-back. The agent edits the stripped file; acceptance must
    land in the commented original without a git merge (DEC-19). Because line
    numbers agree, the agent's line-level edit (difflib, blank lines as junk)
    is replayed onto the original: unchanged lines come from the original
    (comments included), new lines from the agent, and the block-comment
    fragments of replaced/deleted lines are kept so `/- … -/` stays balanced.
    An insertion that would land inside a block comment is moved before it.
    Invariant checked before anything is written:

        nonblank(strip(merged)) == nonblank(strip(accepted))

    i.e. the merged file has exactly the agent's code, plus comments.

CLI:
  strip_comments.py stats FILE...              # comment lines / bytes per file
  strip_comments.py strip --in-place FILE...   # strip (line-preserving)
  strip_comments.py strip --out OUT FILE       # strip one file to OUT
  strip_comments.py merge ORIG ACCEPTED [--out OUT]
"""
import argparse
import difflib
import hashlib
import os
import re
import sys

_IDENT_TAIL = re.compile(r"[\w'!?₀-₉ₐ-ₜᵢ-ᵪ]", re.UNICODE)
_CHAR_LIT = re.compile(
    r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^'\\\n])'")


def comment_spans(text):
    """[(start, end, kind)] of every comment, kind in {"line", "block"}.
    Offsets are into `text`; `end` is exclusive and, for line comments,
    stops before the newline."""
    spans = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        raw_end = _raw_string_at(text, i) if c == "r" else None
        if c == '"':
            i = _skip_string(text, i)
        elif raw_end is not None:
            i = raw_end
        elif c == "'" and (i == 0 or not _IDENT_TAIL.match(text[i - 1])):
            m = _CHAR_LIT.match(text, i)
            i = m.end() if m else i + 1
        elif c == "«":
            j = text.find("»", i + 1)
            i = n if j < 0 else j + 1
        elif text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            spans.append((i, j, "line"))
            i = j
        elif text.startswith("/-", i):
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
            if depth:
                raise ValueError(f"unterminated block comment at offset {i}")
            spans.append((i, j, "block"))
            i = j
        else:
            i += 1
    return spans


def _skip_string(text, i):
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        else:
            j += 1
    raise ValueError(f"unterminated string at offset {i}")


def _raw_string_at(text, i):
    """`r"…"` / `r#"…"#`: return end offset or None if not a raw string here."""
    if i and _IDENT_TAIL.match(text[i - 1]):
        return None
    m = re.compile(r'r(#*)"').match(text, i)
    if not m:
        return None
    close = '"' + m.group(1)
    j = text.find(close, m.end())
    if j < 0:
        raise ValueError(f"unterminated raw string at offset {i}")
    return j + len(close)


def strip(text):
    """Line-preserving strip: comments blanked, newlines kept, trailing
    whitespace trimmed on every line. Returns (stripped, n_spans)."""
    spans = comment_spans(text)
    out, pos = [], 0
    for s, e, _ in spans:
        out.append(text[pos:s])
        out.append("".join(ch for ch in text[s:e] if ch == "\n"))
        pos = e
    out.append(text[pos:])
    stripped = "".join(out)
    lines = stripped.split("\n")
    stripped = "\n".join(l.rstrip() for l in lines)
    assert stripped.count("\n") == text.count("\n")
    return stripped, len(spans)


def _nonblank(text):
    return [l.rstrip() for l in text.split("\n") if l.strip()]


def _block_fragments(text, spans):
    """Per line (0-based): the block-comment text on that line, or ""."""
    lines = text.split("\n")
    starts, off = [], 0
    for l in lines:
        starts.append(off)
        off += len(l) + 1
    frags = [""] * len(lines)
    for s, e, kind in spans:
        if kind != "block":
            continue
        for k in range(len(lines)):
            ls, le = starts[k], starts[k] + len(lines[k])
            a, b = max(s, ls), min(e, le)
            if a < b:
                frags[k] += text[a:b]
    return frags


def _block_line_spans(text, spans):
    """[(first_line, last_line)] (0-based, inclusive) of block comments."""
    res = []
    for s, e, kind in spans:
        if kind == "block":
            res.append((text.count("\n", 0, s), text.count("\n", 0, e - 1)))
    return res


class MergeError(Exception):
    pass


def merge_back(orig, accepted):
    """Replay the agent's edit onto `orig`. The agent edited strip(orig) (or
    an earlier accept of it — strip is line-preserving, so recomputing it
    here always aligns with `orig`). Raises MergeError if the result would
    not carry exactly the agent's code."""
    stripped, _ = strip(orig)
    spans = comment_spans(orig)
    frags = _block_fragments(orig, spans)
    blocks = _block_line_spans(orig, spans)
    o_lines = orig.split("\n")
    s_lines = stripped.split("\n")
    a_lines = accepted.split("\n")
    n = len(o_lines)

    def inside(boundary):
        """Boundary `i` sits between line i-1 and line i; inside a block
        comment iff that block starts before i and ends at or after i.
        Returns the block's first line, or None."""
        for f, l in blocks:
            if f < boundary <= l:
                return f
        return None

    before = [[] for _ in range(n + 1)]     # lines emitted before orig line k
    keep = ["orig"] * n                     # "orig" | "frag"
    sm = difflib.SequenceMatcher(lambda l: not l.strip(), s_lines, a_lines,
                                 autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace" and i2 - i1 == j2 - j1 and all(
                o_lines[k] == a_lines[j1 + k - i1] for k in range(i1, i2)):
            continue        # the agent's own earlier comments, unchanged
        if tag in ("replace", "delete"):
            for k in range(i1, i2):
                keep[k] = "frag"
        if tag in ("replace", "insert"):
            at = i1
            f = inside(at)
            if f is not None:
                at = f
            before[at].extend(a_lines[j1:j2])

    out = []
    for k in range(n):
        out.extend(before[k])
        if keep[k] == "orig":
            out.append(o_lines[k])
        elif frags[k]:
            out.append(frags[k])
    out.extend(before[n])
    merged = "\n".join(out)

    got, want = _nonblank(strip(merged)[0]), _nonblank(strip(accepted)[0])
    if got != want:
        d = list(difflib.unified_diff(want, got, "accepted", "merged",
                                      lineterm="", n=1))
        raise MergeError("merged file does not reproduce the accepted code:\n"
                         + "\n".join(d[:40]))
    return merged


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def strip_files(paths, root=""):
    """Strip each file in place. Returns per-file stats (relative paths)."""
    report = {}
    for p in paths:
        full = os.path.join(root, p) if root else p
        text = open(full, encoding="utf-8").read()
        stripped, n = strip(text)
        blank_before = sum(1 for l in text.split("\n") if not l.strip())
        blank_after = sum(1 for l in stripped.split("\n") if not l.strip())
        if stripped != text:
            open(full, "w", encoding="utf-8").write(stripped)
        report[p] = {"comments": n,
                     "comment_lines": blank_after - blank_before,
                     "bytes_removed": len(text.encode()) - len(stripped.encode()),
                     "sha256_before": sha256_text(text),
                     "sha256_after": sha256_text(stripped)}
    return report


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stats")
    s.add_argument("files", nargs="+")
    t = sub.add_parser("strip")
    g = t.add_mutually_exclusive_group(required=True)
    g.add_argument("--in-place", action="store_true")
    g.add_argument("--out")
    t.add_argument("files", nargs="+")
    m = sub.add_parser("merge")
    m.add_argument("orig")
    m.add_argument("accepted")
    m.add_argument("--out", help="default: stdout")
    args = ap.parse_args()

    if args.cmd == "stats":
        tot_l = tot_b = 0
        for p in args.files:
            text = open(p, encoding="utf-8").read()
            st, n = strip(text)
            cl = (sum(1 for l in st.split("\n") if not l.strip())
                  - sum(1 for l in text.split("\n") if not l.strip()))
            b = len(text.encode()) - len(st.encode())
            tot_l += cl
            tot_b += b
            print(f"{p}: {n} comments, {cl} comment-only lines, {b} bytes")
        print(f"TOTAL: {tot_l} comment-only lines, {tot_b} bytes")
    elif args.cmd == "strip":
        if args.out:
            if len(args.files) != 1:
                sys.exit("--out takes exactly one input file")
            st, n = strip(open(args.files[0], encoding="utf-8").read())
            open(args.out, "w", encoding="utf-8").write(st)
            print(f"{args.files[0]}: {n} comments removed → {args.out}")
        else:
            for p, r in strip_files(args.files).items():
                print(f"{p}: {r['comments']} comments, "
                      f"{r['bytes_removed']} bytes removed")
    elif args.cmd == "merge":
        rd = lambda p: open(p, encoding="utf-8").read()  # noqa: E731
        try:
            merged = merge_back(rd(args.orig), rd(args.accepted))
        except MergeError as e:
            sys.exit(f"merge failed: {e}")
        if args.out:
            open(args.out, "w", encoding="utf-8").write(merged)
        else:
            sys.stdout.write(merged)
    return 0


if __name__ == "__main__":
    sys.exit(main())
