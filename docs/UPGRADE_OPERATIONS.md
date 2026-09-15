> Historical 4.2/4.3 checkpoint. For the current implementation, use [Inspection and release](INSPECTION_AND_RELEASE.md) and [Implementation stages](IMPLEMENTATION_STAGES.md). Earlier descriptions of in-process image inspection, disabled URL workers, and upload authentication trust are superseded.

# NETRA-Mail 4.2 upgrade operations

This upgrade is implemented in the existing project. The source backup made
before this work is under the Codex task's work/source-backup-20260914-183139
directory. It excludes datasets, evidence databases, model binaries, virtual
environments, and Git internals; those original assets were not replaced.

## Running and testing

From the project root, install requirements.txt and requirements-dev.txt in
the project environment, then run:

    python -m pytest -q
    node --test tests/extension_security.test.cjs
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
    streamlit run dashboard/app.py

Reload the unpacked extension in Chrome after updating its source. Existing
running servers need a restart unless their development reload is active.
No browser-store publication or public deployment was performed.

pytest now discovers the maintained tests/ suite. Historical root-level
network evaluation scripts remain available for deliberate invocation.
Test startup redirects evidence and SQLite writes to temporary storage.

## Access controls

Unconfigured local mode accepts loopback clients only. For a reverse proxy,
enable authentication even when the proxy connects over loopback.

NETRA_REQUIRE_API_AUTH=true enables the existing NETRA_API_ACCESS_KEY
deployment-admin credential. Prefer separate identities using
NETRA_API_IDENTITIES: a JSON array containing subject, role, and key_sha256.
The digest is SHA-256 of a long randomly generated token. Never use example
tokens from tests.

Roles are admin, analyst, auditor, and submitter. Auditors can read but cannot create
records or invoke the legacy evidence-verification GET route, which appends
custody events. Analysts cannot use DELETE. These are single-organization
roles, not tenant isolation or SSO.

Submitter credentials are appropriate for the extension: they can ingest
messages and retrieve only their own analysis/findings/trace. They cannot list
all emails, access cases, or retrieve graphs exposing other investigations.
Optional expires_at timestamps must include a timezone; disabled=true revokes
an identity on the next configuration reload. Expiry is checked on each request.
If all configured identities are disabled, local-admin fallback remains closed.

Configure NETRA_ALLOWED_ORIGINS and NETRA_EXTENSION_ID for the actual clients.
The extension popup stores its backend token in the computer's local Chrome profile;
it persists across browser restarts, is not synchronized, and is never exposed to Gmail page scripts. The dashboard uses
NETRA_API_ACCESS_KEY as its client credential (including an identity token).
The packaged extension defaults to the deployed Render backend and dashboard.

## Authentication and models

Set NETRA_TRUSTED_AUTHSERV_IDS to a comma-separated list of receiving systems
whose Authentication-Results headers are within your delivery trust boundary
(for example mx.google.com only when MIME came directly from the authorized
Gmail API connector). NETRA independently verifies DKIM and ARC against DNS,
then evaluates DMARC alignment using verified DKIM and SPF reported by those
trusted receivers. A gateway can call verify_spf_context with its actual SMTP
client IP, MAIL FROM and HELO; this uses bounded SPF DNS processing. Never trust
Authentication-Results from arbitrary uploaded EML files.

Original EML uploads now verify up to three DKIM signatures with dkimpy
1.1.8 and bounded DNS lookups. DNS failures are unavailable, not failures.
Reconstructed API/Gmail messages cannot establish original-byte authenticity.
Supplied Authentication-Results remain explicitly unverified reports.
SPF, complete DMARC policy evaluation, and ARC trust validation remain pending.

The email dataset is backend/data/training_data.csv by default; a URL,label
dataset is rejected. The existing email model remains data/phishing_model.joblib.
NETRA_EMAIL_DATASET_PATH and NETRA_MODEL_PATH can override these paths.
Missing/corrupt models are not silently retrained during requests.
NETRA_MODEL_SHA256 optionally pins the trusted model artifact before loading.
Only provision trusted model files: joblib is not a safe untrusted-file format.
The existing small model is diagnostic in v2 and does not raise blocking risk
without a validated model policy.

## Evidence and limits

New legacy-ledger records hash their verdict and append under a SQLite write
transaction. Old records retain their historical hash format and do not gain
verdict coverage retroactively. Hashes are not externally anchored signatures;
a privileged attacker rewriting all local state remains outside this guarantee.

Reconstructed evidence has its own type. Empty evidence inventories no longer
report verified integrity. Storage path checks prevent traversal during evidence
verification. Requests are bounded before multipart/JSON parsing. In-process
URL expansion is disabled even if an older feature flag requests it; safe
remote inspection requires an isolated service.

### Encryption and custody configuration

NETRA_EVIDENCE_KEYS_JSON is a JSON object mapping key IDs to base64-encoded
32-byte AES keys, supplied by your secret manager. NETRA_EVIDENCE_ACTIVE_KEY
selects the key used for new evidence versions and reports.
NETRA_REQUIRE_EVIDENCE_ENCRYPTION=true fails startup if no active key exists.

The service uses AES-256-GCM with fresh random nonces, authenticates storage
references, and verifies plaintext hashes after decryption. Keep old keys
available until all objects encrypted with them have expired or been migrated.
Keys are not generated or stored by the service. Never put real keys in Git.
No deployment key was configured automatically: existing records stay readable
and are not silently rewritten. New writes without a configured key remain
plaintext, explicitly identified in evidence metadata.

This protects evidence/report file contents when enabled. SQLite investigation
metadata is not encrypted by this feature; use appropriate volume/database
protection and access controls for that separate scope.

Custody, case timeline, and report events now carry the authenticated request
identity. Report events preserve failed verification states. Successful report
downloads are recorded. Archive inspection has a total decompression budget;
DNS enrichment is limited to eight unique domains and bounded query time.
At most eight request bodies/mutations are admitted concurrently per process.

## Evaluation

    python -m evaluation.evaluate_v2 --output evaluation_results/v2.json

This runs the bundled synthetic corpus offline. For independent labels, add
--manifest with a JSON list of path and malicious (boolean) entries; paths
are relative to the manifest. The caller must verify dataset independence,
licensing, and label quality. Synthetic regression results are not production
accuracy. The existing reply-to mismatch sample remains below the default
risk threshold; domain mismatch alone is also possible in legitimate mail.

## Remaining product work

### Image and reputation configuration

Raster image attachments receive bounded decoding, QR extraction and portable
OCR. QR URLs join the normal URL
analysis pipeline. OCR text contributes to analysis but is replaced in stored
parsed output by its hash and character count. Image decoding never executes
embedded content.

URL reputation is disabled by default because enabling it discloses URLs to
external providers. Set NETRA_URL_REPUTATION_ENABLED=true and provide one or
both credentials through a secret manager: NETRA_URLHAUS_AUTH_KEY for URLhaus
and NETRA_GOOGLE_SAFE_BROWSING_KEY for Google Safe Browsing. Requests use fixed
HTTPS endpoints, reject redirects, cap input,
time and responses, and cache verdicts for 15 minutes. Provider availability or
silence never marks a URL safe. Confirm provider terms and privacy requirements
before deployment.

### Hosted preparation added in this pass

Set NETRA_DEPLOYMENT_MODE=hosted to enforce minimum configuration on startup.
Provide NETRA_PUBLIC_ORIGIN as your HTTPS origin, NETRA_EXTENSION_ID as the
installed Chrome extension ID, explicit NETRA_ALLOWED_ORIGINS, configured API
identities (including an admin), required evidence encryption and explicit
persistent database/evidence paths. Run python -m backend.deployment_guard
with that environment before starting the server. This check does not validate
TLS termination, database-volume encryption, backups or external isolation.

The extension popup now accepts a server origin. Remote servers must use HTTPS;
Chrome requests permission for the selected host. The session key is bound to
that exact origin. Changing the origin never forwards the previous key. The
popup explains that analysis sends the visible message to the chosen server.
The optional host permission follows Chrome's permissions API:
https://developer.chrome.com/docs/extensions/reference/api/permissions

For an explicitly selected test mailbox message, configure an OAuth access
token using the deployment secret manager as NETRA_MAILBOX_ACCESS_TOKEN,
NETRA_PUBLIC_ORIGIN and a scoped NETRA_API_ACCESS_KEY. Run:

    python -m backend.mailbox_ingestion --provider gmail --message-id MESSAGE_ID

Use --provider microsoft for Graph. Tokens are not CLI arguments or saved by
this adapter. The Gmail raw-message and Graph MIME endpoints preserve original
bytes. Provider token acquisition, refresh, consent UI, background ingestion,
and real-account acceptance are not implemented by this adapter.
References:
https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get
https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0

The CI workflow runs Python/extension tests and a dependency vulnerability scan
with a CycloneDX report. It has not been executed on GitHub in this task.
The local dependency audit was rerun after upgrading pytest to fix the advisory
reported for the prior installation. A clean dependency scan is not a pentest.

Content checks now include combined payment-change instructions, mixed-script
domains, HTML payload assembly and direction-control characters. These are
static signals; QR/OCR and attachment detonation remain outstanding.

Evaluation rejects duplicate bytes, invalid labels, mismatched supplied hashes
and paths outside the manifest folder. Reports include p95 latency and overall
correct fraction including failed cases. Dataset independence is never inferred
from the presence of a manifest.

- Independent email/BEC/multilingual datasets, calibrated scoring, and model drift evaluation.
- Authenticated Gmail/Microsoft ingestion and genuine pre-interaction prevention.
- SSO, full tenant authorization, automated credential lifecycle and external audit storage.
- Deployment key provisioning, metadata encryption, retention/legal holds and external anchoring.
- Isolated URL/attachment detonation, QR/image analysis and maintained reputation sources.
- Full SPF/DMARC/ARC verification with trusted delivery context.
- Production queues, distributed limits, durable database deployment and recovery exercises.
- Independent security assessment and real-browser extension acceptance testing.

The completed changes are a tested upgrade, not a claim of production readiness
or immunity to attack.
