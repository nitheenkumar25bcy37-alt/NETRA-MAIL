# Local setup and submission candidate

## Install

Use Python 3.11 or later and Docker Desktop in Linux-container mode. Create a
virtual environment, then install `requirements.txt`, `requirements-dev.txt` and
optionally `requirements-gmail.txt`. The source candidate excludes trained model
files; provision a trusted model separately or use the documented heuristic mode.

From the project root, build the inspection image:

```powershell
docker build -f inspection/Dockerfile -t netra-inspector:4.4.0 .
python -m backend.operational_status
python scripts/start_local.py
```

On Windows, the local launcher detects the unpacked Chrome extension whose
installed path exactly matches this project's `extension` directory and allows
that single `chrome-extension://` origin. If detection is unavailable, set
`NETRA_EXTENSION_ID` to the 32-character ID shown on `chrome://extensions`
before starting the backend. Do not reuse an ID from a different project copy.

In a second terminal, start the dashboard with its loopback-only launcher:

```powershell
python scripts/start_dashboard.py
```

Open `http://127.0.0.1:8501`. Avoid invoking Streamlit without an explicit
loopback address on a local demonstration machine because its default binding
can make the dashboard reachable from other network interfaces.

The Dockerfile-specific ignore file sends only the worker source and dependencies
to the builder. It does not send NETRA databases, mail, model files or secrets.
The worker receives attachment bytes via stdin and returns bounded JSON on stdout.
It has no host mounts, no evidence keys, a read-only root filesystem, a temporary
32 MiB filesystem, no Linux capabilities, no new privileges, UID 65532, 768 MiB
memory, one CPU, 64 processes/threads, 25 CPU seconds and 30 seconds wall time.
The host also imposes a 35-second deadline and removes the named container after
completion or failure. At most two containers run concurrently per API process;
each message inspects at most four attachments within a 60-second dispatch budget.

Static workers use `--network=none`. URL workers use a separate one-shot process
with no attachment input, only public HTTP/HTTPS on standard ports, validated DNS
answers, a pinned socket address and certificate verification. Each redirect is
revalidated; no cookies, credentials, proxy environment or response body are used.
Private/link-local/loopback/multicast and IPv6 translation ranges are rejected.
Application fetch policy is not an infrastructure egress firewall. Production
requires a dedicated worker host with independent network policy and runtime
hardening; a container is not a full malware-detonation VM.

The controls use Docker's documented runtime options:
https://docs.docker.com/engine/containers/run/

## Optional external intelligence

```powershell
python scripts/start_local.py --reputation --expand-urls
```

The launcher prompts for missing Google Safe Browsing / URLhaus keys with hidden
input. Enter skips a provider; at least one key is required. Keys stay in the
launched process environment and are not written to configuration files. Existing
secret-manager environment variables can be used instead. Reputation discloses
URLs to providers; expansion contacts the URL destination. Both remain opt-in.

## Gmail

```powershell
python -m backend.gmail_local --client C:/path/to/desktop-oauth-client.json
```

Only the server-fetched Gmail original can enable `mx.google.com` header trust.
An optional `NETRA_TRUSTED_AUTHSERV_IDS` allowlist can restrict that authority.
Arbitrary uploads remain untrusted regardless of that variable. Microsoft
original MIME retrieval is supported; Microsoft receiver-header trust is not
automatically enabled. OAuth refresh persistence and background ingestion are
post-submission work.

## Checkpoint packaging

```powershell
python scripts/package_submission.py --output C:/path/to/netra-4.4.0-candidate.zip
```

The ZIP includes source, configuration examples, documentation and a checksum
manifest. Runtime evidence, databases, credentials, models and private emails are
excluded by file selection. This is a source backup, not an evidence backup.
`requirements-submission.lock` records the installed Windows package versions;
it is not a cross-platform or hash-verified dependency lock. The container has its
own Linux dependencies. Build and retain its image digest for deployment.

Do not call the candidate a verified release until the deferred backend/extension
checks, secret/dependency scans, independent evaluation and live workflows pass.
The source manifest deliberately records acceptance as deferred.

## Recovery and limitations

If Docker stops, analysis reports unavailable attachment content inspection.
Restart Docker and rebuild the named image, then reanalyze affected messages.
No risky content is executed in the API as a recovery fallback. Existing metadata,
text and URL heuristics can still run; a low score is not proof of attachment safety.
OCR language accuracy, animation frames beyond the first and large/many-attachment
messages remain limited. Missing threat-intelligence keys do not imply safe URLs.
Existing tests have not been rerun for 4.4.0 at the user's request.
