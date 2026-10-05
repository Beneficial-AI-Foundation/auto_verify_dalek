"""SessionStart(compact) hook: remind the agent to reread durable workflow inputs."""
import json
import sys
from pathlib import Path


def main():
    event = json.load(sys.stdin)
    if event.get("hook_event_name") != "SessionStart" or event.get("source") != "compact":
        return
    root = Path(sys.argv[1]).resolve()
    files = [root / "workflow.md", root / "round-context.md"]
    if (root / "lean-check.md").exists():
        files.append(root / "lean-check.md")
    reminder = (
        "Context compaction has just completed. Before continuing, reread these "
        "harness-provided workflow files with Read:\n"
        + "\n".join(str(path) for path in files)
        + "\nFollow any relevant workflow/skill references in them. These files "
        "capture this invocation's starting instructions and handoff, not live "
        "proof progress. Reconcile them with subsequent conversation, current "
        "source and the latest check logs; do not undo newer progress. Then "
        "continue autonomously, choosing your own proof strategy and check timing."
    )
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "SessionStart", "additionalContext": reminder}}))


if __name__ == "__main__":
    main()
