"""Bounded, hole-free consumer obligations over abstract helper interfaces.

This lowering supports explicit, typed function binders and expression bodies.
Unsupported Lean syntax fails closed; it is never reported as feasible merely
because a statement elaborates. Source definitions come from the frozen Git tree.
"""

from __future__ import annotations

import re
import secrets

from .contracts import ContractError


def compile_source(run, source, guard_path):
    """Compile frozen inputs in a disposable lane with no canonical authority."""
    from . import worker_runtime as runtime
    from .candidate_lane import _sealed_lane_exec, _sealed_source_digest
    lane_id = f"feasibility-{secrets.token_hex(12)}"
    root = f"/volume/lanes/{lane_id}/work"
    archive = runtime._git(run, "archive", "--format=tar", run["base_commit"])
    runtime._docker(*runtime._runtime_argv(
        run["lock"], run["volume"], "sh", "-eu", "-c",
        'test ! -e "$1"; mkdir -p "${1%/*}"; mkdir "$1"; tar -xf - -C "$1"',
        "sh", root,
    ), input_bytes=archive)
    before = _sealed_source_digest(run, root, guard_path)
    completed = runtime._docker(*runtime._candidate_runtime_argv(
        run["lock"], run["volume"], lane_id,
        *_sealed_lane_exec(
            ".", guard_path, "sh", "-c",
            "lake build 2>&1 && lake env lean --stdin 2>&1; code=$?; "
            "printf '\\nAUTOFV_FEASIBILITY_EXIT=%s\\n' \"$code\"",
            detach_git=True,
        ),
    ), input_bytes=source.encode("utf-8"))
    if _sealed_source_digest(run, root, guard_path) != before:
        raise runtime.WorkerError("feasibility compilation modified isolated source")
    return completed


_NAME = r"[A-Za-z_][A-Za-z0-9_'.]*(?:\.[A-Za-z_][A-Za-z0-9_']*)*"
_FORBIDDEN = re.compile(r"\b(?:sorry|admit|axiom|unsafe|run_elab|run_tac|set_option|by)\b|[\n\r;]|--|/\*")


def _signature(text, kind, name):
    if not isinstance(text, str) or _FORBIDDEN.search(text) or ":=" in text:
        raise ContractError("unsupported feasibility signature syntax")
    match = re.fullmatch(rf"{kind}\s+{re.escape(name)}\s*(.+)", text.strip())
    if match is None:
        raise ContractError("unsupported feasibility declaration signature")
    rest = match.group(1)
    binders = []
    # Balanced explicit binders only. Inferred/implicit/instance parameters need
    # a Lean elaborator lowering and must not be guessed by a text parser.
    while rest.startswith("("):
        depth, end = 0, None
        for index, char in enumerate(rest):
            depth += (char == "(") - (char == ")")
            if depth == 0:
                end = index + 1
                break
        if end is None or ":" not in rest[:end]:
            raise ContractError("unsupported feasibility binder")
        binder = rest[:end]
        if re.fullmatch(r"\(\s*[A-Za-z_][A-Za-z0-9_']*\s*:\s*.+\)", binder) is None:
            raise ContractError("unsupported feasibility binder")
        binders.append(binder)
        rest = rest[end:].strip()
    if not rest.startswith(":"):
        raise ContractError("unsupported feasibility binder")
    result = rest[1:].strip()
    if _FORBIDDEN.search(result) or ":=" in result:
        raise ContractError("unsupported feasibility proposition")
    return binders, result


def _definition(source, declaration):
    short = declaration.rsplit(".", 1)[-1]
    matches = list(re.finditer(rf"^def\s+({re.escape(declaration)}|{re.escape(short)})\s+([^\n]+)$", source, re.M))
    if len(matches) != 1 or ":=" not in matches[0].group(0):
        raise ContractError("unsupported feasibility source definition")
    header, body = matches[0].group(0).split(":=", 1)
    name = matches[0].group(1)
    binders, result = _signature(header, "def", name)
    if _FORBIDDEN.search(body):
        raise ContractError("unsupported feasibility source body")
    return binders, result, body.strip()


def _replace(text, names):
    for old in sorted(names, key=len, reverse=True):
        text = re.sub(rf"(?<![\w.']){re.escape(old)}(?![\w.'])", lambda _: names[old], text)
    return text


def _proposition(item, names):
    declaration = item["declaration"]
    if not item["canon"].startswith(f"theorem {declaration} "):
        declaration = declaration.rsplit(".", 1)[-1]
    binders, result = _signature(item["canon"], "theorem", declaration)
    proposition = ("∀ " + " ".join(binders) + ", " if binders else "") + result
    return _replace(proposition, names)


def consumer_source(request, sources):
    """Generate two separate checks: interface elaboration and sufficiency."""
    items = {item["node"]: item for item in request["obligations"]}
    modules = request["modules"]
    if any(re.fullmatch(_NAME, module) is None for module in modules):
        raise ContractError("invalid feasibility module")
    lines = [*(f"import {module}" for module in modules), ""]
    qualified = {node.removeprefix("probe:").rsplit(".", 1)[-1]: node.removeprefix("probe:") for node in items}
    for item in items.values():
        # A proposition-valued expression checks elaboration without any proof
        # hole or declaration that might be mistaken for a consumer proof.
        lines.append(f"#check ({_proposition(item, qualified)} : Prop)")
    for consumer, item in items.items():
        dependencies = [value for value in items.values() if any(
            parent["node"] == consumer for parent in value["immediate_consumers"])]
        if not dependencies:
            continue
        names, parameters = {}, []
        for index, dependency in enumerate(dependencies):
            declaration = dependency["node"].removeprefix("probe:")
            binders, result, _ = _definition(sources[dependency["source_path"]], declaration)
            typ = ("∀ " + " ".join(binders) + ", " if binders else "") + result
            parameter = f"_autofv_dep_{index}"
            parameters.append(f"({parameter} : {typ})")
            for name in (declaration, declaration.rsplit(".", 1)[-1]):
                if name in names and names[name] != parameter:
                    raise ContractError("ambiguous feasibility dependency name")
                names[name] = parameter
        declaration = consumer.removeprefix("probe:")
        binders, _, body = _definition(sources[item["source_path"]], declaration)
        body = _replace(body, names)
        # Every prepared project dependency must be abstracted; unlisted project
        # declarations in a body fail closed instead of expanding graph authority.
        for node in items:
            name = node.removeprefix("probe:")
            if re.search(rf"(?<![\w.']){re.escape(name)}(?![\w.'])", body):
                raise ContractError("unabstracted feasibility dependency")
        expression = f"(fun {' '.join(binders)} => {body})" if binders else f"({body})"
        hypotheses = [f"(_autofv_h{index} : {_proposition(dependency, names)})"
                      for index, dependency in enumerate(dependencies)]
        consumer_names = {**names, declaration: expression,
                          declaration.rsplit('.', 1)[-1]: expression}
        goal = _proposition(item, consumer_names)
        rules = ", ".join(f"_autofv_h{index}" for index in range(len(dependencies)))
        lines.extend(["", f"example {' '.join(parameters + hypotheses)} : {goal} := by",
                      f"  simp only [{rules}]"])
    return "\n".join(lines) + "\n"
