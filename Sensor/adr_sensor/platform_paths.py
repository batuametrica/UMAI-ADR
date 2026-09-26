"""Platform-aware filesystem roots for Claude products and IDE-hosted agents.

UMAI: added. Upstream resolves paths inline in each parser, which hardcodes the
macOS layout. This module centralizes root discovery so Windows and macOS are
first-class, and returns *candidate lists* rather than single paths — Claude
Desktop on Windows is mid-migration from %APPDATA% to %LOCALAPPDATA%, so both
have to be probed.

The VS Code family (Cursor, VS Code, Insiders, VSCodium, Windsurf) shares one
user-data layout, so Cursor's state DB and Cline's task store resolve from the
same `<base>/<Product>/User` roots.
"""

import os
import sys
from pathlib import Path
from typing import List, Sequence

# Agent-mode session layouts. Which one applies is platform-dependent:
# macOS writes an audit log per session directory; Windows writes a metadata
# sidecar that points at a Claude Code transcript.
LAYOUT_AUDIT_JSONL = "audit_jsonl"
LAYOUT_SIDECAR = "sidecar"


# VS Code-family products whose user data lives at <base>/<Product>/User.
# Cursor comes first so its roots win wherever order matters.
CURSOR_PRODUCT = "Cursor"
VSCODE_FAMILY_PRODUCTS = (CURSOR_PRODUCT, "Code", "Code - Insiders", "VSCodium", "Windsurf")

# Cline's extension id — its tasks live in each host's globalStorage.
CLINE_EXTENSION_ID = "saoudrizwan.claude-dev"


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


def _vscode_family_base() -> Path:
    """Per-user application-data base the VS Code family writes under."""
    home = Path.home()

    if sys.platform == "darwin":
        return home / "Library" / "Application Support"

    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return Path(base) if base else home / "AppData" / "Roaming"

    return home / ".config"


def vscode_family_user_roots(products: Sequence[str] = VSCODE_FAMILY_PRODUCTS) -> List[Path]:
    """`<base>/<Product>/User` for every installed VS Code-family product.

    base is %APPDATA% on Windows, ~/Library/Application Support on macOS and
    ~/.config on Linux.
    """
    base = _vscode_family_base()
    return _existing([base / product / "User" for product in products])


def cursor_state_db() -> List[Path]:
    """Cursor's global state database (composer and bubble data)."""
    return _existing(
        [root / "globalStorage" / "state.vscdb" for root in vscode_family_user_roots((CURSOR_PRODUCT,))]
    )


def cline_task_roots() -> List[Path]:
    """Cline task directories in every VS Code-family host it can be installed in."""
    return _existing(
        [root / "globalStorage" / CLINE_EXTENSION_ID / "tasks" for root in vscode_family_user_roots()]
    )


def codex_sessions() -> List[Path]:
    """Codex CLI rollout store: $CODEX_HOME/sessions, else ~/.codex/sessions.

    Codex itself uses CODEX_HOME exclusively when it is set, so the default is
    not probed as a fallback.
    """
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return _existing([Path(codex_home).expanduser() / "sessions"])
    return _existing([Path.home() / ".codex" / "sessions"])
