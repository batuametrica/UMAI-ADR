"""Tests for platform-aware root discovery (VS Code family, Cline, Codex)."""

import json
import sys
from pathlib import Path

import pytest

from adr_sensor import platform_paths
from adr_sensor.parsers.cline_parser import ClineParser
from adr_sensor.parsers.codex_parser import CodexParser
from adr_sensor.parsers.cursor_parser import CursorParser

PLATFORM_BASES = {
    # sys.platform -> application-data base relative to the fake home
    "win32": Path("AppData") / "Roaming",
    "darwin": Path("Library") / "Application Support",
    "linux": Path(".config"),
}


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


def _use_platform(monkeypatch, home: Path, platform: str) -> Path:
    """Switch sys.platform and return the VS Code-family base for it."""
    monkeypatch.setattr(sys, "platform", platform)
    base = home / PLATFORM_BASES[platform]
    if platform == "win32":
        monkeypatch.setenv("APPDATA", str(base))
    else:
        monkeypatch.delenv("APPDATA", raising=False)
    return base


def _write_cline_task(root: Path, name: str) -> None:
    task_dir = root / name
    task_dir.mkdir(parents=True)
    (task_dir / "api_conversation_history.json").write_text(
        json.dumps(
            [
                {"role": "user", "content": [{"type": "text", "text": f"task {name}"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "Done."}]},
            ]
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize("platform", sorted(PLATFORM_BASES))
class TestVscodeFamilyRoots:
    def test_user_roots_only_existing_products(self, fake_home, monkeypatch, platform):
        base = _use_platform(monkeypatch, fake_home, platform)
        for product in ("Cursor", "Code - Insiders", "Windsurf"):
            (base / product / "User").mkdir(parents=True)
        (base / "SomethingElse" / "User").mkdir(parents=True)

        roots = platform_paths.vscode_family_user_roots()

        assert roots == [
            base / "Cursor" / "User",
            base / "Code - Insiders" / "User",
            base / "Windsurf" / "User",
        ]

    def test_cursor_state_db(self, fake_home, monkeypatch, platform):
        base = _use_platform(monkeypatch, fake_home, platform)
        assert platform_paths.cursor_state_db() == []

        db = base / "Cursor" / "User" / "globalStorage" / "state.vscdb"
        db.parent.mkdir(parents=True)
        db.write_bytes(b"")
        # A VS Code state DB is not Cursor's.
        other = base / "Code" / "User" / "globalStorage" / "state.vscdb"
        other.parent.mkdir(parents=True)
        other.write_bytes(b"")

        assert platform_paths.cursor_state_db() == [db]
        assert CursorParser().db_path == db

    def test_cline_task_roots_every_host(self, fake_home, monkeypatch, platform):
        base = _use_platform(monkeypatch, fake_home, platform)
        expected = []
        for product in platform_paths.VSCODE_FAMILY_PRODUCTS:
            tasks = base / product / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "tasks"
            tasks.mkdir(parents=True)
            expected.append(tasks)
        # A host without Cline installed contributes nothing.
        (base / "VSCodium" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "tasks").rmdir()
        expected = [p for p in expected if "VSCodium" not in p.parts]

        assert platform_paths.cline_task_roots() == expected


def test_windows_without_appdata_falls_back_to_roaming(fake_home, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("APPDATA", raising=False)
    root = fake_home / "AppData" / "Roaming" / "Cursor" / "User"
    root.mkdir(parents=True)

    assert platform_paths.vscode_family_user_roots() == [root]


def test_windows_does_not_probe_macos_or_linux_layout(fake_home, monkeypatch):
    base = _use_platform(monkeypatch, fake_home, "win32")
    (fake_home / ".config" / "Cursor" / "User").mkdir(parents=True)
    (fake_home / "Library" / "Application Support" / "Cursor" / "User").mkdir(parents=True)

    assert platform_paths.vscode_family_user_roots() == []
    (base / "Cursor" / "User").mkdir(parents=True)
    assert platform_paths.vscode_family_user_roots() == [base / "Cursor" / "User"]


class TestCodexSessions:
    def test_default_home(self, fake_home):
        assert platform_paths.codex_sessions() == []
        sessions = fake_home / ".codex" / "sessions"
        sessions.mkdir(parents=True)

        assert platform_paths.codex_sessions() == [sessions]
        assert CodexParser().base_path == sessions

    def test_codex_home_wins(self, fake_home, tmp_path, monkeypatch):
        (fake_home / ".codex" / "sessions").mkdir(parents=True)
        custom = tmp_path / "codex-home"
        (custom / "sessions").mkdir(parents=True)
        monkeypatch.setenv("CODEX_HOME", str(custom))

        assert platform_paths.codex_sessions() == [custom / "sessions"]
        assert CodexParser().base_path == custom / "sessions"

    def test_codex_home_set_but_missing_is_not_default(self, fake_home, tmp_path, monkeypatch):
        (fake_home / ".codex" / "sessions").mkdir(parents=True)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "absent"))

        assert platform_paths.codex_sessions() == []

    def test_explicit_base_path_wins(self, fake_home, tmp_path):
        (fake_home / ".codex" / "sessions").mkdir(parents=True)
        assert CodexParser(base_path=str(tmp_path)).base_path == tmp_path


class TestClineMultiRoot:
    def test_discovers_tasks_in_every_host(self, fake_home, monkeypatch):
        base = _use_platform(monkeypatch, fake_home, "win32")
        for product, task in (("Cursor", "1700000000001"), ("Code", "1700000000002"), ("Windsurf", "1700000000003")):
            _write_cline_task(
                base / product / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "tasks", task
            )

        parser = ClineParser()
        entries = parser.parse_all()

        assert len(parser.base_paths) == 3
        assert sorted(e.session_id for e in entries) == [
            "cline_1700000000001",
            "cline_1700000000002",
            "cline_1700000000003",
        ]

    def test_no_roots(self, fake_home, monkeypatch, capsys):
        _use_platform(monkeypatch, fake_home, "linux")
        parser = ClineParser()

        assert parser.base_paths == []
        assert parser.base_path is None
        assert parser.parse_all() == []
        assert "[CLINE] No logs found" in capsys.readouterr().out

    def test_explicit_base_path_is_single_root(self, fake_home, monkeypatch, tmp_path):
        base = _use_platform(monkeypatch, fake_home, "win32")
        _write_cline_task(base / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "tasks", "ignored")
        _write_cline_task(tmp_path / "explicit", "picked")

        parser = ClineParser(base_path=str(tmp_path / "explicit"))
        assert [e.session_id for e in parser.parse_all()] == ["cline_picked"]
