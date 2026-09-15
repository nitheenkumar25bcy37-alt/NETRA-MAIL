# NETRA 4.4.0 test and acceptance record

Date: 2026-09-15

## Passed

- Python suite: 147 passed with six dependency deprecation warnings.
- Chrome extension static/security suite: 4 passed.
- Docker static worker: one-shot execution passed under the configured non-root,
  read-only, network-disabled and resource-limited container options.
- API-to-worker flow: controlled EML upload returned HTTP 200, attachment
  inspection completed, and evidence registration succeeded using temporary
  storage.
- Failure containment: timeout, missing worker image and malformed worker input
  returned bounded structured failures without crashing the API.
- Network policy: a loopback URL was blocked in the isolated URL worker.
- Archive controls: a high-compression ZIP remained bounded while its executable
  member produced a critical finding.
- Dashboard: loaded against a temporary 4.4.0 backend; summary and recent-email
  requests returned HTTP 200. The new launcher listened only on `127.0.0.1`.
- Python dependency audit: no known vulnerabilities were reported. CycloneDX and
  JSON results are stored in the external task output folder.
- Credential-pattern scan: no matches in the scoped project source. Runtime data,
  deterministic fixtures, virtual environments and databases were excluded.
- Synthetic offline evaluation: 20 messages, zero processing errors, 15 TP,
  4 TN, 0 FP, 1 FN, precision 1.0, recall 0.9375, F1 0.9677, false-positive
  rate 0.0, expected-decision fraction 0.95 and p95 latency 2.275 seconds.

## Fixes made during acceptance

- Updated stale authentication regression expectations so trusted Gmail headers
  require a server-fetched Gmail original.
- Updated reputation mocks for bounded streaming responses.
- Updated the URL-expansion regression for the opt-in worker behavior.
- Corrected blocked URL inspection to report `available: false`.
- Added a loopback-only dashboard launcher after the default Streamlit invocation
  advertised LAN/external interfaces.
- Added a regression proving configured `mx.google.com` trust does not apply to
  arbitrary uploaded EML.
- Added a Gmail badge link to the exact SOC dashboard investigation. The URL
  contains only the analysis UUID, opens with `noopener noreferrer`, and never
  contains the email body or API credential. The dashboard validates the UUID
  and renders that email directly with a back-to-overview action. A live local
  deep link opened the expected 0/100 stored investigation successfully.
- Fixed local Chrome origin discovery after live acceptance exposed two unpacked
  project copies with different extension IDs. The launcher now allows only the
  ID whose installed path exactly matches the current project; ambiguous or
  missing matches fail closed. A request with the current extension origin
  returned HTTP 200 and the same CORS origin, and 25 focused tests passed.

## External acceptance still required

- Real Chrome/Gmail extension tests: Chrome is not exposed to this Codex
  session's browser-control bridge. The in-app browser cannot load or validate
  the unpacked Chrome extension.
- Live Gmail connector/authentication samples: requires the user's authorized
  Gmail test account and Desktop OAuth client configuration.
- Google Safe Browsing and URLhaus: credentials are absent, so safe/malicious
  live lookups, invalid-key, provider rate-limit and provider-outage checks remain.
- Independent detection evaluation: no independently sourced, licensed and
  reviewed labeled dataset was supplied.
- Full DKIM/ARC/SPF/DMARC live matrix and Indian-language OCR accuracy: suitable
  signed messages and reviewed language samples were not supplied.

The synthetic result is regression evidence only. The source candidate must not
be described as independently validated or production-ready until the external
items above are completed.

## Real Chrome/Gmail acceptance progress

- Benign message: passed on 2026-09-15. A real Internshala message displayed the
  badge `NETRA LOW RISK · 0/100 · REVIEW` beside the currently open subject.
- The extension returned reconstructed-message limitations and correctly kept
  DKIM, ARC, SPF and DMARC unavailable with `delivery_source: untrusted_upload`.
  It did not claim that visible Gmail fields authenticate the delivered bytes.
- Extension origin correction: passed after the local launcher selected the
  current OneDrive extension ID. The earlier `Origin not permitted` response is
  resolved.
- Controlled phishing/link, QR, message-switching, backend outage/recovery and
  invalid-key cases remain to be exercised in the real Chrome profile.
