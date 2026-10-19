"""Controller-owned, reconstructible specification input for type expectations.

The snapshot is separate from the submitted proof tree. Its extension language
is deliberately narrow: reviewed theorem stubs and lexical scopes, never new
executable elaborators. The actual context is compiled, not interpreted here.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from pathlib import PurePosixPath
from typing import Any

from .contracts import ContractError, canonical_json_bytes


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _without_comments(text: str) -> str:
    out, depth, i = [], 0, 0
    while i < len(text):
        if text.startswith("/-", i):
            depth += 1
            out.append(" ")
            i += 2
        elif depth and text.startswith("-/", i):
            depth -= 1
            i += 2
        elif not depth and text.startswith("--", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        else:
            out.append(text[i] if not depth or text[i] == "\n" else " ")
            i += 1
    if depth:
        raise ContractError("reviewed source has an unfinished comment")
    return "".join(out)


def validate_extension(baseline: str, reviewed: str, declaration: str, canon: str) -> None:
    """Authorize only a proof-free theorem addition over exact pristine code.

    Existing context (including notation, variables and instances) is untouched.
    New namespace/open/section wrappers are inert lexical input. This does not
    authorize model-authored initializers, macros, instances or type elaborators.
    """
    changes = difflib.SequenceMatcher(None, baseline.splitlines(keepends=True),
                                     reviewed.splitlines(keepends=True), autojunk=False)
    added = []
    significant_insertions = 0
    for tag, _a, _b, c, d in changes.get_opcodes():
        if tag in {"replace", "delete"}:
            raise ContractError("reviewed expectation changed pristine source")
        if tag == "insert":
            insertion = "".join(reviewed.splitlines(keepends=True)[c:d])
            significant_insertions += bool(_without_comments(insertion).strip())
            added.append(insertion)
    if significant_insertions > 1:
        raise ContractError("reviewed expectation scope crosses pristine commands")
    if not added:
        # Existing declarations get their type from the pristine source, too.
        return
    extension = "".join(added)
    if any(not char.isprintable() and char not in "\n\t" for char in extension):
        raise ContractError("reviewed expectation has unsupported control characters")
    code = _without_comments(extension)
    # No strings/quotation or meta-evaluation in the new header/context. Trusted
    # baseline syntax is preserved verbatim and is not subject to this filter.
    if any(char in code for char in ('"', '`', '«', '»', '#')) or re.search(
        r"\b(?:unsafe|partial|initialize|builtin_initialize|elab|macro|syntax|"
        r"run_tac|run_elab|run_meta|eval_expr|implemented_by|extern|csimp)\b", code
    ):
        raise ContractError("reviewed expectation introduces executable elaboration")
    name = declaration.rsplit('.', 1)[-1]
    match = re.search(r"\btheorem\s+([A-Za-z_][A-Za-z0-9_.']*)\s+(.*?)"
                      r"\s*:=\s*by\s+sorry\b", code, re.S)
    if match is None or match[1].rsplit('.', 1)[-1] != name:
        raise ContractError("reviewed expectation is not one proof-free theorem")
    header = "theorem " + declaration + " " + match[2]
    if " ".join(header.split()) != " ".join(canon.split()) or re.search(r"\b(?:by|do)\b", match[2]):
        raise ContractError("reviewed expectation statement/context mismatch")
    before = code[:match.start()].rstrip()
    if before.endswith("@[step]"):
        before = before[:-len("@[step]")]
    remaining = before + "\n" + code[match.end():]
    scopes = []
    for line in remaining.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"\s*(namespace|section|end|open(?:\s+scoped)?)"
                             r"((?:\s+[A-Za-z_][A-Za-z0-9_.']*)*)\s*", line)
        if match is None:
            raise ContractError("reviewed expectation has unsupported added context")
        names = match[2].split()
        if match[1] in {"namespace", "section"}:
            if len(names) > 1 or match[1] == "namespace" and not names:
                raise ContractError("reviewed expectation scope is invalid")
            scopes.append(names[0] if names else None)
        elif match[1] == "end":
            if not scopes or len(names) > 1 or names and names[0] != scopes[-1]:
                raise ContractError("reviewed expectation closes a pristine scope")
            scopes.pop()
        elif not scopes:
            raise ContractError("reviewed expectation open escapes its local scope")
    if scopes:
        raise ContractError("reviewed expectation leaves a scope open")


def make(*, declaration: str, canon: str, path: str, source: str,
         baseline_source: str, base_commit: str, review_sha256: str) -> dict[str, Any]:
    body = {"schema": "autofv-reviewed-source/v1", "declaration": declaration,
            "canon_sha256": _sha(canon.encode()), "path": path, "source": source,
            "source_sha256": _sha(source.encode()), "base_source_sha256": _sha(baseline_source.encode()),
            "base_commit": base_commit, "review_sha256": review_sha256}
    snapshot = {**body, "snapshot_sha256": _sha(canonical_json_bytes(body))}
    validate(snapshot, declaration=declaration, canon=canon, base_commit=base_commit,
             baseline_source=baseline_source)
    return snapshot


def validate(value: Any, *, declaration: str, canon: str, base_commit: str,
             baseline_source: str | None = None) -> dict[str, Any]:
    fields = {"schema", "declaration", "canon_sha256", "path", "source", "source_sha256",
              "base_source_sha256", "base_commit", "review_sha256", "snapshot_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractError("reviewed expectation snapshot fields mismatch")
    if (value['schema'] != 'autofv-reviewed-source/v1' or value['declaration'] != declaration
        or value['base_commit'] != base_commit or not isinstance(base_commit, str)
        or re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', base_commit) is None):
        raise ContractError("reviewed expectation snapshot identity mismatch")
    path = PurePosixPath(value['path']) if isinstance(value['path'], str) else PurePosixPath('/')
    if (path.is_absolute() or path.suffix != '.lean' or path.as_posix() != value['path']
        or any(part.startswith('.') for part in path.parts)
        or '\\' in value['path'] or any(ord(char) < 32 for char in value['path'])):
        raise ContractError("reviewed expectation source path is unsafe")
    if not isinstance(value['source'], str) or len(value['source'].encode()) > 1_000_000:
        raise ContractError("reviewed expectation source is invalid")
    for field in ('canon_sha256', 'source_sha256', 'base_source_sha256', 'review_sha256', 'snapshot_sha256'):
        if not isinstance(value[field], str) or re.fullmatch(r'[0-9a-f]{64}', value[field]) is None:
            raise ContractError("reviewed expectation hash is invalid")
    body = {k: v for k, v in value.items() if k != 'snapshot_sha256'}
    if (value['snapshot_sha256'] != _sha(canonical_json_bytes(body))
        or value['source_sha256'] != _sha(value['source'].encode())
        or value['canon_sha256'] != _sha(canon.encode())):
        raise ContractError("reviewed expectation snapshot hash mismatch")
    from .fvs_adapter import validate_statement_source
    validate_statement_source(canon, value['source'])
    if baseline_source is not None:
        if value['base_source_sha256'] != _sha(baseline_source.encode()):
            raise ContractError("reviewed expectation pristine source drift")
        validate_extension(baseline_source, value['source'], declaration, canon)
    return value
