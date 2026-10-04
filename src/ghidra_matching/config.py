"""User preferences from user_preferences.cfg (see user_preferences.example.cfg)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

REPO = Path(__file__).resolve().parents[2]
CONFIG_ENV = "GHIDRA_MATCHING_CONFIG"
DEFAULTS = {
    "EXPORT_DIR": "exports",
    "OUT_DIR": "out",
    "BUILD_NAME_FORMAT": "{year}-{month:02d}-{day:02d}",
}


def preferences_path() -> Path:
    return Path(os.environ.get(CONFIG_ENV) or REPO / "user_preferences.cfg")


def parse(text: str) -> Dict[str, str]:
    prefs: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        prefs[key.strip()] = value.strip()
    return prefs


class Preferences:
    """Lookup order: environment variable, preferences file, built-in default."""

    def __init__(self, values: Optional[Dict[str, str]] = None, path: Optional[Path] = None):
        self.path = path or preferences_path()
        if values is None:
            values = parse(self.path.read_text("utf-8")) if self.path.is_file() else {}
        self.values = values

    def get(self, key: str) -> Optional[str]:
        return os.environ.get(key) or self.values.get(key) or DEFAULTS.get(key) or None

    def path_value(self, key: str) -> Optional[Path]:
        """A path preference; relative paths are relative to the repository."""
        v = self.get(key)
        if not v:
            return None
        p = Path(v)
        return p if p.is_absolute() else REPO / p
