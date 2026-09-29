"""Explicit, pinned FVS input for the isolated to_bytes experiment."""
import hashlib
import json
from pathlib import Path
import shutil

BUNDLE = Path(__file__).resolve().parent / "fv_skill_bundle"
SKILL = "fv-harness:lean-verify"


def manifest(root=BUNDLE):
    root = Path(root)
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"skill bundle contains a symlink: {path}")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    upstream = json.loads((root / "upstream.json").read_text())
    for path, digest in upstream["reference_sha256"].items():
        if files.get(path) != digest:
            raise ValueError(f"pinned FV reference changed: {path}")
    if set(p.relative_to(root).as_posix() for p in root.rglob("SKILL.md")) != {
        "skills/lean-verify/SKILL.md"
    }:
        raise ValueError("FV bundle must expose exactly lean-verify")
    return {"skill": SKILL, "upstream": upstream, "files_sha256": files,
            "adapter": "headless-single-session"}


def prompt():
    return (f"\nBefore starting the proof, invoke the Skill tool with skill={SKILL} "
            "and the target spec file path as args. Follow its headless proof workflow "
            "within the editable-file and verification rules above. If the skill "
            "cannot be loaded, report that failure instead of silently running without it.\n")


def invocation_evidence(transcript):
    """Distinguish installing a skill from actually loading it successfully."""
    calls, successful = {}, set()
    for line in Path(transcript).read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        message = event.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if not isinstance(block, dict):
                continue
            if event.get("type") == "assistant" and block.get("type") == "tool_use" and block.get("name") == "Skill":
                calls[block["id"]] = block.get("input", {}).get("skill")
            if event.get("type") == "user" and block.get("type") == "tool_result" and not block.get("is_error", False):
                successful.add(block.get("tool_use_id"))
    return {"requested": list(calls.values()),
            "loaded": any(name == SKILL and call in successful for call, name in calls.items())}


def prepare(config_dir, settings_path):
    """Copy only the selected plugin; return paths to mount read-only and evidence."""
    evidence = manifest()
    config = Path(config_dir)
    plugin = config / "fv-plugin"
    shutil.copytree(BUNDLE, plugin)
    settings = json.loads(Path(settings_path).read_text())
    settings.update(syncClaudeAiSkills=False, disableBundledSkills=True,
                    enabledPlugins={})
    settings.setdefault("skillOverrides", {}).update({
        "doctor": "off", "init": "off", "security-review": "off",
    })
    permissions = settings.setdefault("permissions", {})
    permissions.setdefault("deny", []).extend(["Agent", "Task", "WebFetch", "WebSearch"])
    permissions["deny"].extend([
        f"Skill({name}{suffix})"
        for name in ("doctor", "init", "security-review") for suffix in ("", " *")
    ])
    settings_file = config / "fv-settings.json"
    settings_file.write_text(json.dumps(settings, indent=2) + "\n")
    evidence["settings_sha256"] = hashlib.sha256(settings_file.read_bytes()).hexdigest()
    (config / "fv-manifest.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return str(plugin), str(settings_file), evidence
