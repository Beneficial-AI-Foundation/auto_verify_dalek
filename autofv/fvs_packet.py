"""Complete public-source DATA packets and exact, non-fuzzy candidate overlays."""
from __future__ import annotations

import copy
import hashlib
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from .contracts import ContractError, _exact_dict, canonical_json_bytes
from .fvs_profile import digest

MAX_BYTES = 262144
SURFACES = {"rust", "lean", "types", "interpretation", "intent"}


def safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(c) < 32 for c in value):
        raise ContractError("FVS source path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(p.startswith(".") for p in path.parts):
        raise ContractError("FVS hidden/escaping source path refused")
    if any(p.lower() in {"proof-engineering", "validation", "private", "credentials"} for p in path.parts):
        raise ContractError("FVS private/lesson source refused")
    return value


def source(path: str, surface: str, content: str) -> dict[str, Any]:
    raw = content.encode("utf-8")
    return {"path": safe_path(path), "surface": surface, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "content": content}


def _read(root: Path, relative: str) -> str:
    path = root / safe_path(relative)
    if root.is_symlink() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ContractError("FVS symlink source refused")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ContractError("FVS source missing or escaping approved root")
    if path.stat().st_size > MAX_BYTES:
        raise ContractError("FVS source exceeds packet bound")
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ContractError("FVS source is unreadable") from exc


def _identity(value: Any) -> dict[str, Any]:
    identity = _exact_dict(value, {"repository", "revision", "tree_sha256"}, "FVS source identity")
    if (not isinstance(identity["repository"], str) or not identity["repository"]
        or not isinstance(identity["revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", identity["revision"]) is None
        or not isinstance(identity["tree_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", identity["tree_sha256"]) is None):
        raise ContractError("FVS provenance identity invalid")
    return identity


def validate_packet(value: Any) -> dict[str, Any]:
    packet = _exact_dict(value, {"schema", "source_identity", "sources", "style", "grounding", "packet_sha256"}, "FVS source packet")
    if packet["schema"] != "autofv-fvs-source-packet/v1":
        raise ContractError("FVS source packet schema mismatch")
    _identity(packet["source_identity"])
    raw = canonical_json_bytes(packet)
    if len(raw) > MAX_BYTES or packet["packet_sha256"] != digest({k: v for k, v in packet.items() if k != "packet_sha256"}):
        raise ContractError("FVS complete packet hash/bound mismatch")
    sources = packet["sources"]
    if not isinstance(sources, list) or not sources:
        raise ContractError("FVS source packet is empty")
    indexed: dict[str, dict[str, Any]] = {}
    for item in sources:
        _exact_dict(item, {"path", "surface", "bytes", "sha256", "content"}, "FVS source")
        path = safe_path(item["path"])
        if (path in indexed or item["surface"] not in SURFACES
            or not isinstance(item["content"], str) or not item["content"].strip()
            or "\x00" in item["content"] or "\r" in item["content"]
            or type(item["bytes"]) is not int
            or source(path, item["surface"], item["content"]) != item):
            raise ContractError("FVS duplicate/malformed/changed source")
        if ((item["surface"] == "rust") != path.startswith("rust/")
            or (item["surface"] == "rust" and not path.endswith(".rs"))):
            raise ContractError("FVS Rust source namespace/type mismatch")
        indexed[path] = item
    if not SURFACES <= {s["surface"] for s in sources}:
        raise ContractError("FVS missing source surface")
    style = _exact_dict(packet["style"], {"path", "content", "max_columns", "max_namespace_dots"}, "FVS style data")
    if (not isinstance(style["content"], str) or not style["content"].strip()
        or type(style["max_columns"]) is not int or not 1 <= style["max_columns"] <= 100
        or type(style["max_namespace_dots"]) is not int or not 0 <= style["max_namespace_dots"] <= 2):
        raise ContractError("FVS style limits invalid")
    if style["path"] != "FVS fallback" and (safe_path(style["path"]) not in indexed
        or indexed[style["path"]]["content"] != style["content"]):
        raise ContractError("FVS style guide missing from complete packet")
    validate_grounding(packet["grounding"], indexed)
    return copy.deepcopy(packet)


def validate_grounding(value: Any, indexed: dict[str, dict[str, Any]]) -> None:
    inventory = _exact_dict(value, {"version", "declarations", "cited_apis", "limitations"}, "FVS grounding")
    if inventory["version"] != 1 or type(inventory["version"]) is not int or not isinstance(inventory["limitations"], str):
        raise ContractError("FVS grounding version/limitations invalid")
    if (not isinstance(inventory["declarations"], list) or len(inventory["declarations"]) > 30
        or not isinstance(inventory["cited_apis"], list) or len(inventory["cited_apis"]) > 60
        or not inventory["cited_apis"]):
        raise ContractError("FVS grounding incomplete/oversized")
    charged = 0
    def span(item: Any, analog: bool = False) -> None:
        nonlocal charged
        _exact_dict(item, {"path", "start", "end"} | ({"handling"} if analog else set()), "FVS grounding span")
        path = safe_path(item["path"])
        if (path not in indexed or type(item["start"]) is not int or type(item["end"]) is not int
            or not 1 <= item["start"] <= item["end"] <= len(indexed[path]["content"].splitlines())
            or item["end"] - item["start"] >= 40):
            raise ContractError("FVS grounding source/span missing")
        if analog and item["handling"] not in {"REUSE-AS-IS", "EXTEND", "ADAPTER", "JUSTIFY-FORK"}:
            raise ContractError("FVS reuse disposition invalid")
        charged += item["end"] - item["start"] + 1
    for decl in inventory["declarations"]:
        _exact_dict(decl, {"name", "signature", "analogs", "search"}, "FVS grounding declaration")
        search = _exact_dict(decl["search"], {"queries", "roots", "conclusion"}, "FVS grounding searches")
        if (not all(isinstance(decl[k], str) and decl[k].strip() for k in ("name", "signature"))
            or not isinstance(decl["analogs"], list) or len(decl["analogs"]) > 5
            or not isinstance(search["conclusion"], str) or not search["conclusion"].strip()
            or any(not isinstance(search[k], list) or not search[k]
                   or any(not isinstance(s, str) or not s.strip() for s in search[k]) for k in ("queries", "roots"))):
            raise ContractError("FVS grounding research incomplete")
        for item in decl["analogs"]:
            span(item, True)
    for item in inventory["cited_apis"]:
        span(item)
    if charged > 200:
        raise ContractError("FVS grounding exceeds 200 charged signature lines")


def _read_pinned_rust(root: Path, identity: dict[str, Any], relative: str) -> str:
    """Authenticate only named public Rust bytes; never traverse source-clone Lean."""
    _identity(identity)
    if root.parts[-2:] != ("curve25519-dalek", "src") or not relative.endswith(".rs"):
        raise ContractError("FVS Rust root/path is not the approved public src subtree")
    content = _read(root, relative)
    command = ["git", "--no-replace-objects", "-C", str(root)]
    try:
        def git(*args: str) -> str:
            return subprocess.run(command + list(args), check=True, capture_output=True,
                                  timeout=30).stdout.decode("utf-8")
        if (git("rev-parse", "HEAD").strip() != identity["revision"]
            or git("config", "--get", "remote.origin.url").strip() != identity["repository"]
            or git("rev-parse", "--show-prefix").strip() != "curve25519-dalek/src/"):
            raise ContractError("FVS Rust preparation provenance mismatch")
        # Use the immutable revision, not HEAD, after checking checkout provenance.
        committed = git("show", identity["revision"] + ":curve25519-dalek/src/" + relative)
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise ContractError("FVS pinned public Rust source unavailable") from exc
    if committed != content:
        raise ContractError("FVS public Rust bytes differ from pinned revision")
    return content


def build_packet(*, prepared_root: Path, rust_root: Path, source_identity: dict[str, Any],
                 preparation: dict[str, Any], paths: list[dict[str, str]],
                 style: dict[str, Any], grounding: dict[str, Any]) -> dict[str, Any]:
    """Read only explicitly named public Rust/prepared files; never traverse solved Lean.

    rust_root must be the public curve25519-dalek/src subtree of the pinned
    preparation source checkout. A different Rust revision requires new provenance.
    """
    _identity(source_identity)
    if preparation.get("source") != source_identity or not isinstance(preparation.get("files"), list):
        raise ContractError("FVS builder requires preparation provenance/file inventory")
    prepared_files = {s["path"]: s for s in preparation["files"]}
    sources = []
    for item in paths:
        _exact_dict(item, {"path", "surface"}, "FVS explicit source path")
        path = safe_path(item["path"])
        rust = item["surface"] == "rust"
        if rust != path.startswith("rust/") or (rust and not path.endswith(".rs")):
            raise ContractError("FVS source root/type mismatch")
        if not rust and path not in prepared_files:
            raise ContractError("FVS source is not in the spoiler-free preparation inventory")
        content = (_read_pinned_rust(rust_root, source_identity, path.removeprefix("rust/"))
                   if rust else _read(prepared_root, path))
        if not rust and hashlib.sha256(content.encode()).hexdigest() != prepared_files[path]["sha256"]:
            raise ContractError("FVS prepared source hash drift")
        sources.append(source(path, item["surface"], content))
    body = {"schema": "autofv-fvs-source-packet/v1", "source_identity": source_identity,
            "sources": sources, "style": style, "grounding": grounding}
    return validate_packet({**body, "packet_sha256": digest(body)})


def bind_original(packet: Any, *, prepared_root: Path, preparation: dict[str, Any],
                  source_paths: list[str], rust_root: Path | None = None) -> dict[str, Any]:
    packet = validate_packet(packet)
    if packet["source_identity"] != preparation.get("source"):
        raise ContractError("FVS packet preparation source identity drift")
    if rust_root is None:
        raise ContractError("FVS ingestion requires an explicit pinned public Rust root")
    indexed = {s["path"]: s for s in packet["sources"]}
    if not isinstance(preparation.get("files"), list):
        raise ContractError("FVS original packet lacks preparation file inventory")
    prepared_files = {s["path"]: s for s in preparation["files"]}
    if not set(source_paths) <= indexed.keys():
        raise ContractError("FVS packet omits graph sources")
    for path, item in indexed.items():
        if item["surface"] == "rust":
            if _read_pinned_rust(rust_root, packet["source_identity"], path.removeprefix("rust/")) != item["content"]:
                raise ContractError("FVS packet differs from pinned public Rust bytes")
        else:
            if (path not in prepared_files or prepared_files[path]["sha256"] != item["sha256"]
                or _read(prepared_root, path) != item["content"]):
                raise ContractError("FVS packet differs from prepared source bytes/inventory")
    return packet


def apply_patch(original: str, path: str, patch: str) -> str:
    """Apply exact unified hunks to original bytes, without fuzz, shell or writes."""
    from . import worker
    worker.validate_assigned_patch(path, patch)
    lines = original.splitlines(keepends=True)
    diff = patch.splitlines(keepends=True)
    out: list[str] = []
    cursor = 0
    i = next((j for j, line in enumerate(diff) if line.startswith("@@ ")), len(diff))
    if i == len(diff):
        raise ContractError("FVS candidate has no exact source hunk")
    while i < len(diff):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?", diff[i])
        if match is None:
            raise ContractError("FVS malformed patch hunk")
        start, old_count, new_start, new_count = (int(match[1]), int(match[2] or 1), int(match[3]), int(match[4] or 1))
        pos = start - 1 if old_count else start
        if pos < cursor or pos > len(lines):
            raise ContractError("FVS reordered/escaping patch hunk")
        out.extend(lines[cursor:pos])
        if (new_start - 1 if new_count else new_start) != len(out):
            raise ContractError("FVS patch new-source position mismatch")
        cursor = pos
        old_seen = new_seen = 0
        i += 1
        while i < len(diff) and not diff[i].startswith("@@ "):
            line = diff[i]
            if not line or line[0] not in " +-":
                raise ContractError("FVS unsupported patch metadata/no-newline hunk")
            if line[0] in " -":
                if cursor >= len(lines) or lines[cursor] != line[1:]:
                    raise ContractError("FVS patch source drift")
                cursor += 1
                old_seen += 1
            if line[0] in " +":
                out.append(line[1:])
                new_seen += 1
            i += 1
        if (old_seen, new_seen) != (old_count, new_count):
            raise ContractError("FVS patch hunk counts mismatch")
    out.extend(lines[cursor:])
    return "".join(out)


def dependency_snapshot(original: Any, binding: dict[str, Any], overlays: list[dict[str, Any]]) -> dict[str, Any]:
    packet = {"schema": "autofv-fvs-dependency-packet/v1", "original_packet": validate_packet(original),
              "dependency_generation": copy.deepcopy(binding), "dependency_overlays": copy.deepcopy(overlays)}
    validate_view(packet)
    return packet


def validate_view(packet: Any) -> dict[str, dict[str, Any]]:
    """Resolve immutable accepted dependencies, then the author's exact own overlay."""
    if packet.get("schema") == "autofv-fvs-source-packet/v1":
        return {s["path"]: s for s in validate_packet(packet)["sources"]}
    review = packet.get("schema") == "autofv-fvs-review-packet/v1"
    fields = {"schema", "original_packet"}
    if review:
        fields |= {"original_packet_sha256", "overlay", "patch", "patch_sha256"}
    elif packet.get("schema") != "autofv-fvs-dependency-packet/v1":
        raise ContractError("FVS source view schema mismatch")
    dependency = "dependency_generation" in packet
    if dependency or not review:
        fields |= {"dependency_generation", "dependency_overlays"}
    _exact_dict(packet, fields, "FVS source view")
    original = validate_packet(packet["original_packet"])
    sources = {s["path"]: s for s in original["sources"]}
    if dependency:
        binding = _exact_dict(packet["dependency_generation"], {
            "schema", "run_id", "node", "graph_sha256", "original_base_commit", "original_packet_sha256",
            "dependencies", "accepted_nodes", "accepted_commit", "accepted_tree_sha256", "frozen_contracts_sha256",
            "dependency_report_hashes", "source_hashes", "generation_sha256"}, "FVS dependency generation")
        if (binding["schema"] != "autofv-fvs-lane-generation/v1"
            or any(not isinstance(binding[k], str) or not binding[k] for k in ("run_id", "node"))
            or any(not isinstance(binding[k], str) or re.fullmatch(r"[0-9a-f]{40}", binding[k]) is None
                   for k in ("original_base_commit", "accepted_commit"))
            or any(not isinstance(binding[k], str) or re.fullmatch(r"[0-9a-f]{64}", binding[k]) is None
                   for k in ("graph_sha256", "original_packet_sha256", "accepted_tree_sha256", "frozen_contracts_sha256", "generation_sha256"))
            or any(not isinstance(binding[k], list) or any(not isinstance(n, str) or not n for n in binding[k])
                   or binding[k] != sorted(set(binding[k])) for k in ("dependencies", "accepted_nodes"))
            or not set(binding["dependencies"]) <= set(binding["accepted_nodes"])
            or binding["node"] in binding["accepted_nodes"]
            or not isinstance(binding["dependency_report_hashes"], dict)
            or set(binding["dependency_report_hashes"]) != set(binding["accepted_nodes"])
            or any(not isinstance(h, str) or re.fullmatch(r"[0-9a-f]{64}", h) is None for h in binding["dependency_report_hashes"].values())):
            raise ContractError("FVS dependency generation identity invalid")
        if binding.get("generation_sha256") != digest({k: v for k, v in binding.items() if k != "generation_sha256"}):
            raise ContractError("FVS dependency generation hash drift")
        if binding.get("original_packet_sha256") != original["packet_sha256"]:
            raise ContractError("FVS dependency original source drift")
        overlays = packet["dependency_overlays"]
        if not isinstance(overlays, list) or [s["path"] for s in overlays] != sorted({s["path"] for s in overlays}):
            raise ContractError("FVS dependency overlay order/duplicates")
        for item in overlays:
            path = safe_path(item["path"])
            if (path not in sources or sources[path]["surface"] == "rust"
                or item["surface"] != sources[path]["surface"] or source(path, item["surface"], item["content"]) != item):
                raise ContractError("FVS dependency overlay source drift")
            sources[path] = item
        hashes = {p: s["sha256"] for p, s in sources.items() if s["surface"] != "rust"}
        if hashes != binding.get("source_hashes"):
            raise ContractError("FVS dependency source hash drift")
    if review:
        item = packet["overlay"]
        path = item["path"]
        if (path not in sources or sources[path]["surface"] == "rust"
            or packet["original_packet_sha256"] != original["packet_sha256"]
            or packet["patch_sha256"] != hashlib.sha256(packet["patch"].encode()).hexdigest()
            or item != source(path, sources[path]["surface"], apply_patch(sources[path]["content"], path, packet["patch"]))):
            raise ContractError("FVS candidate source overlay drift")
        sources[path] = item
    if len(canonical_json_bytes(packet)) > MAX_BYTES:
        raise ContractError("FVS complete source view exceeds bound")
    return copy.deepcopy(sources)


def review_snapshot(packet: Any, *, path: str, patch: str) -> dict[str, Any]:
    sources = validate_view(packet)
    dependencies = {k: copy.deepcopy(packet[k]) for k in ("dependency_generation", "dependency_overlays") if k in packet}
    original = validate_packet(packet.get("original_packet", packet))
    if path not in sources or sources[path]["surface"] == "rust":
        raise ContractError("FVS candidate overlay source missing")
    current = apply_patch(sources[path]["content"], path, patch)
    snapshot = {"schema": "autofv-fvs-review-packet/v1", "original_packet": original,
                "original_packet_sha256": original["packet_sha256"], **dependencies,
                "overlay": source(path, sources[path]["surface"], current),
                "patch": patch, "patch_sha256": hashlib.sha256(patch.encode()).hexdigest()}
    validate_view(snapshot)
    return snapshot
