"""Interactive local Gmail connection; OAuth tokens remain in memory only."""
import argparse
import json
import os
from pathlib import Path

import requests
from backend.mailbox_ingestion import bounded_response, ingest_selected, validate_backend_origin

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def authorize(path):
    from google_auth_oauthlib.flow import InstalledAppFlow
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    installed = config.get("installed", {})
    # Only Google's endpoints may receive this desktop client configuration.
    if installed.get("auth_uri") != "https://accounts.google.com/o/oauth2/auth" or installed.get("token_uri") != "https://oauth2.googleapis.com/token":
        raise ValueError("Use a Google Cloud Desktop app OAuth client JSON file")
    flow = InstalledAppFlow.from_client_config(config, [SCOPE], autogenerate_code_verifier=True)
    return flow.run_local_server(host="127.0.0.1", port=0, timeout_seconds=180,
        authorization_prompt_message="Sign in using the browser window opened by NETRA.",
        success_message="Gmail connected. You can close this tab and return to NETRA.")


def recent_ids(token):
    with requests.Session() as session:
        session.trust_env = False
        response = session.get("https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"Authorization": "Bearer " + token}, params={"maxResults": 10, "labelIds": "INBOX"},
            timeout=(5, 10), stream=True, allow_redirects=False)
        data = json.loads(bounded_response(response, 65536))
        return [item["id"] for item in data.get("messages", []) if isinstance(item.get("id"), str)]


def main():
    parser = argparse.ArgumentParser(description="Connect Gmail locally and analyze one selected inbox message")
    parser.add_argument("--client", required=True, help="Path to Google Desktop OAuth client JSON")
    parser.add_argument("--message-id", help="Optional Gmail API message ID")
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    validate_backend_origin(args.backend)
    # Check backend before asking the user to complete Google sign-in.
    with requests.Session() as session:
        session.trust_env = False
        bounded_response(session.get(args.backend.rstrip("/") + "/ready", timeout=(3, 5),
            allow_redirects=False, stream=True), 65536)
    print("Google will request read-only Gmail access. Tokens are kept only until this program exits.")
    credentials = authorize(args.client)
    message_id = args.message_id
    if not message_id:
        ids = recent_ids(credentials.token)
        if not ids:
            print("No inbox messages found.")
            return
        for index, identifier in enumerate(ids, 1):
            print(f"{index}. Gmail message {identifier}")
        choice = input("Choose a message number to analyze (Enter cancels): ").strip()
        if not choice:
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(ids):
            raise ValueError("Select a listed message number")
        message_id = ids[int(choice) - 1]
    print("The Gmail access token will be sent to " + args.backend + " to fetch and analyze the selected original email, including attachments. Use only a backend you trust; the token permits read-only mailbox access until it expires.")
    if input("Type ANALYZE to continue: ").strip() != "ANALYZE":
        return
    result = ingest_selected("gmail", message_id, credentials.token, args.backend,
        os.getenv("NETRA_API_ACCESS_KEY", ""))
    print(json.dumps({key: result.get(key) for key in ("email_id", "classification", "risk_score", "evidence_reference")}, indent=2))
    print("Analysis saved. Open the NETRA dashboard to review the case and evidence.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, requests.RequestException) as exc:
        print("Connection or analysis failed (" + type(exc).__name__ + "). Check backend availability, client setup and consent.")
        raise SystemExit(1)
