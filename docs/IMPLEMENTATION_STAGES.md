# NETRA 4.4.0 implementation checkpoint

The current user request defers testing and acceptance. This document separates
implemented code from deployment inputs and release approval. The earlier stage
proposal is planning context, not evidence that a feature was completed.

| Stage | Existing implementation | Work in this checkpoint | Remaining |
|---|---|---|---|
| 1 Chrome/Gmail | Extension message identity checks, backend connection, badges, scoped credentials | Corrected current-project origin discovery; benign live message passed; extension 3.4.0 links each badge to the matching dashboard investigation | Remaining malicious, switching and outage browser cases |
| 2 Independent evaluation | Manifest validation, deduplication, hashes, precision/recall/F1, latency, HTML reports | Retained evaluator; no invented labels or scoring changes | Independent licensed data and evaluation deferred |
| 3 Reputation | Google Safe Browsing and URLhaus clients | Stream-bounded responses, memory-only key setup, configuration inventory | User/provider credentials and activation; live acceptance deferred |
| 4 Authentication | DKIM, ARC, SPF context and DMARC identifier alignment | Server-side selected-message retrieval; Gmail trust only on that route; uploaded headers never trusted | Live acceptance deferred; full DMARC DNS-policy evaluation remains outside this alignment implementation |
| 5 QR/OCR | QR targets and OCR feed detection; routine OCR text removed | Bounded raster for both native decoders, first-frame and language limitations, worker execution | Accuracy/language acceptance deferred |
| 6 Isolated inspection | In-process static analysis and disabled fetch | One-shot non-root containers, no host mounts/secrets, static worker without network, CPU/memory/file/process/time limits, controlled public-IP HEAD redirects, bounded tasks, structured unavailable results | Worker image `netra-inspector:4.4.0` is installed; runtime acceptance is deferred |
| 7 Submission | Existing runbook and CI | Updated operations, source-only packaging, version manifest, SHA-256 checksums, environment dependency lock | Testing/scans/review deferred; candidate is not a verified final release |

Docker Desktop is running and the local `netra-inspector:4.4.0` Linux/amd64 image
is installed with digest
`sha256:5479d351f20d636188239e891c26f60fe8a88afe674c0c8832fc6e76c8cce11c`.
Its configured user is `65532:65532` and its entry point is
`python -m backend.inspection_worker`. Runtime acceptance remains deferred under
the user's instruction to leave testing phases until the implementation stages
are complete.

## Acceptance progress — 2026-09-15

- Python suite: 147 passed, including the final Gmail trust regression.
- Chrome extension static/security suite: 4 passed.
- Isolated worker: successful one-shot static inspection under runtime limits.
- Worker failure behavior: timeout, missing image and malformed protocol returned
  structured unavailable results without crashing the API.
- URL isolation: loopback destination blocked by the container worker.
- Archive limits: high-ratio ZIP inspection was bounded while retaining a critical
  executable-member finding.
- Connected API flow: a temporary v2 upload invoked the Docker worker, returned
  HTTP 200, marked attachment inspection complete and registered evidence.
- Dashboard: rendered against a temporary 4.4.0 backend and loaded summary/email
  endpoints successfully; safe launcher bound only to `127.0.0.1`.
- Dependency audit: no known vulnerabilities.
- Tracked-source credential pattern scan: no matches.
- Synthetic offline regression: 20 processed, 0 errors, 95% expected decisions,
  precision 1.0, recall 0.9375, F1 0.9677 and p95 latency 2.275 seconds. These are
  synthetic regression figures and do not establish production accuracy.

Real Chrome/Gmail, live reputation providers, independent held-out data, signed
authentication variants and QR/OCR language accuracy still require external
accounts, credentials, data or user-visible Chrome access.

## Scope after submission

PostgreSQL, Redis, organizational SSO, complete tenant isolation, managed secrets,
TLS deployment, monitoring, recovery exercises, external audit anchoring,
penetration testing and Chrome Web Store publication were explicitly listed as
post-submission work in the supplied plan. They are not silently counted as done.

## Compatibility changes

- Gmail/Microsoft local adapters call `/api/v2/mailbox/analyze`. The backend
  receives a short-lived provider token to fetch the selected original. Tokens
  are not saved to the evidence ledger or returned in analysis results. Use only
  a trusted backend; read-only OAuth scope still grants mailbox read access.
- Attachment inspection requires the installed Docker image. Unavailable workers
  preserve metadata findings and explicitly report incomplete content inspection.
  There is no automatic in-process decoder fallback.
- Direct tests that mocked in-process image/attachment analysis or trusted upload
  headers will need adjustment during the deferred testing phase.
- Existing cryptographic success still does not establish message safety.
