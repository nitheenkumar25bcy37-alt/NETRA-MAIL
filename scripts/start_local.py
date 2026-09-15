"""Launch local NETRA with optional, memory-only reputation key entry."""
import argparse
import getpass
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def detect_unpacked_extension_id(root, user_data=None):
    """Find Chrome's ID only when its unpacked path exactly matches this project."""
    expected = (Path(root) / "extension").resolve()
    base = Path(user_data) if user_data else Path(os.getenv("LOCALAPPDATA", "")) / "Google/Chrome/User Data"
    if not base.is_dir():
        return ""
    matches = []
    for preferences in base.glob("*/Secure Preferences"):
        try:
            settings = json.loads(preferences.read_text(encoding="utf-8")).get("extensions", {}).get("settings", {})
        except (OSError, ValueError, TypeError):
            continue
        for extension_id, record in settings.items():
            if not re.fullmatch(r"[a-p]{32}", extension_id) or not isinstance(record, dict):
                continue
            try:
                installed_path = Path(str(record.get("path", ""))).resolve()
            except (OSError, ValueError):
                continue
            if str(installed_path).casefold() == str(expected).casefold():
                matches.append(extension_id)
    return sorted(set(matches))[0] if len(set(matches)) == 1 else ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reputation", action="store_true", help="Disclose analyzed URLs to configured reputation providers")
    parser.add_argument("--expand-urls", action="store_true", help="Allow the isolated worker to contact public URL destinations")
    args = parser.parse_args()
    env = dict(os.environ)
    root = Path(__file__).resolve().parents[1]
    if not env.get("NETRA_EXTENSION_ID"):
        extension_id = detect_unpacked_extension_id(root)
        if extension_id:
            env["NETRA_EXTENSION_ID"] = extension_id
            print("Allowing the unpacked extension for this project: " + extension_id)
    if args.reputation:
        print("URL reputation sends message URLs to Google Safe Browsing and/or URLhaus. Keys are not saved.")
        for name, label in (("NETRA_GOOGLE_SAFE_BROWSING_KEY", "Google Safe Browsing key"), ("NETRA_URLHAUS_AUTH_KEY", "URLhaus key")):
            if not env.get(name):
                value = getpass.getpass(label + " (Enter skips provider): ").strip()
                if value:
                    env[name] = value
        if not any(env.get(name) for name in ("NETRA_GOOGLE_SAFE_BROWSING_KEY", "NETRA_URLHAUS_AUTH_KEY")):
            parser.error("At least one reputation provider key is required")
        env["NETRA_URL_REPUTATION_ENABLED"] = "true"
    if args.expand_urls:
        print("The isolated URL worker may contact public web servers using HEAD requests.")
        env["NETRA_EXPAND_SHORT_URLS"] = "1"
    return subprocess.call([sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"], cwd=root, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
