from __future__ import annotations

import json
import os
import re
from pathlib import Path


def detect_unpacked_extension_id(
    root: str | Path,
    user_data: str | Path | None = None,
) -> str:
    """Return Chrome's ID when exactly one unpacked install matches this project."""
    expected = (Path(root) / "extension").resolve()
    base = (
        Path(user_data)
        if user_data is not None
        else Path(os.getenv("LOCALAPPDATA", "")) / "Google/Chrome/User Data"
    )

    if not base.is_dir():
        return ""

    matches: set[str] = set()
    for preferences in base.glob("*/Secure Preferences"):
        try:
            settings = json.loads(
                preferences.read_text(encoding="utf-8")
            ).get("extensions", {}).get("settings", {})
        except (OSError, ValueError, TypeError):
            continue

        for extension_id, record in settings.items():
            if not re.fullmatch(r"[a-p]{32}", extension_id):
                continue
            if not isinstance(record, dict):
                continue

            try:
                installed_path = Path(str(record.get("path", ""))).resolve()
            except (OSError, ValueError):
                continue

            if str(installed_path).casefold() == str(expected).casefold():
                matches.add(extension_id)

    return next(iter(matches)) if len(matches) == 1 else ""
