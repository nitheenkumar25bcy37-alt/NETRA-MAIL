"""Configure the public Google OAuth client ID, never tokens."""
import argparse
import json
import re
from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+-[a-zA-Z0-9]+\.apps\.googleusercontent\.com", args.client_id):
        parser.error("Use a Google Chrome Extension OAuth client ID")
    path = Path(__file__).resolve().parents[1] / "extension" / "manifest.json"
    data = json.loads(path.read_text())
    data["oauth2"] = {"client_id": args.client_id, "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]}
    path.write_text(json.dumps(data, indent=2) + "\n")
    print("Reload extension and Gmail. Consent is requested on Analyze current email.")
