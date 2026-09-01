"""Create a secret-safe support bundle for collector troubleshooting."""

import json
import os
import platform
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

_SECRET_KEY = re.compile(r"(authorization|bootstrap.?token|device.?token|password|secret)", re.I)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(
    r"(?i)((?:authorization|bootstrap.?token|device.?token|password|secret)\s*[:=]\s*)([^\s,;]+)"
)


def _root() -> Path:
    override = os.environ.get("UMAI_ADR_DATA_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "UMAI" / "ADR Collector"
    return Path.home() / ".cache" / "adr_sensor"


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SECRET_KEY.search(str(key)) else _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER.sub(r"\1[REDACTED]", value)
    return value


def _safe_json(path: Path) -> Any:
    try:
        return _redact(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


def _redact_text(value: str) -> str:
    return _ASSIGNMENT.sub(r"\1[REDACTED]", _BEARER.sub(r"\1[REDACTED]", value))


def create_support_bundle(output: Path) -> Path:
    """Write diagnostics and redacted logs; DPAPI blobs and transcript state are excluded."""
    root = _root()
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="umai-adr-support-") as temp_dir:
        staging = Path(temp_dir)
        diagnostics = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "collector_version": __version__,
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": platform.node(),
            "state_root": str(root),
        }
        (staging / "diagnostics.json").write_text(
            json.dumps(diagnostics, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        device = _safe_json(root / "state" / "device.json")
        if device is not None:
            (staging / "device-metadata.json").write_text(
                json.dumps(device, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        config = _safe_json(root / "config" / "collector.json")
        if config is not None:
            (staging / "config.redacted.json").write_text(
                json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        log_dir = root / "logs"
        if log_dir.exists():
            target_logs = staging / "logs"
            target_logs.mkdir()
            for log_path in sorted(log_dir.glob("*.log")):
                try:
                    text = log_path.read_text(encoding="utf-8", errors="replace")
                    text = _redact_text(text)
                    target_logs.joinpath(log_path.name).write_text(text[-2_000_000:], encoding="utf-8")
                except OSError:
                    continue

        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in staging.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(staging))
    return output
