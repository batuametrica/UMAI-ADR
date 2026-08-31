"""Platform-aware filesystem roots for Claude products.

UMAI: added. Upstream resolves paths inline in each parser, which hardcodes the
macOS layout. This module centralizes root discovery so Windows and macOS are
first-class, and returns *candidate lists* rather than single paths — Claude
Desktop on Windows is mid-migration from %APPDATA% to %LOCALAPPDATA%, so both
have to be probed.
"""

import os
import sys
from pathlib import Path
from typing import List

# Agent-mode session layouts. Which one applies is platform-dependent:
# macOS writes an audit log per session directory; Windows writes a metadata
# sidecar that points at a Claude Code transcript.
LAYOUT_AUDIT_JSONL = "audit_jsonl"
LAYOUT_SIDECAR = "sidecar"


def _existing(paths: List[Path]) -> List[Path]:
    """Filter to roots that actually exist, preserving priority order."""
    return [p for p in paths if p.exists()]


def claude_code_projects() -> List[Path]:
    """Claude Code transcript store. Same location on every platform."""
    return _existing([Path.home() / ".claude" / "projects"])


def claude_desktop_data_roots() -> List[Path]:
    """Claude Desktop user-data directories, highest priority first.

    Windows returns both %APPDATA%\\Claude and %LOCALAPPDATA%\\Claude: newer
    builds resolve user data to LOCALAPPDATA and migrate the old directory on
    first run, so during rollout either one can hold the live data.
    """
    home = Path.home()

    if sys.platform == "darwin":
        return _existing([home / "Library" / "Application Support" / "Claude"])

    if sys.platform == "win32":
        candidates = []
        for env_var in ("APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(env_var)
            if base:
                candidates.append(Path(base) / "Claude")
        return _existing(candidates)

    return _existing([home / ".config" / "Claude"])


def claude_desktop_log_roots() -> List[Path]:
    """Claude Desktop log directories (Chrome native-host activity lives here)."""
    home = Path.home()

    if sys.platform == "darwin":
        return _existing([home / "Library" / "Logs" / "Claude"])

    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        return _existing([Path(base) / "Claude" / "Logs"]) if base else []

    return _existing([home / ".config" / "Claude" / "logs"])


def agent_mode_session_root() -> tuple[str, Path] | None:
    """Locate the agent-mode session store and report which layout it uses.

    Returns (layout, path) or None when no agent-mode data is present.
    """
    for root in claude_desktop_data_roots():
        if sys.platform == "win32":
            sidecar_dir = root / "claude-code-sessions"
            if sidecar_dir.exists():
                return LAYOUT_SIDECAR, sidecar_dir
        else:
            audit_dir = root / "local-agent-mode-sessions"
            if audit_dir.exists():
                return LAYOUT_AUDIT_JSONL, audit_dir

    return None
