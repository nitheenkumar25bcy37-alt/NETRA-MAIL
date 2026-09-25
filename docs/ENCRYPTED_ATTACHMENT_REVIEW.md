# Optional encrypted PDF review — NETRA 4.6.0

## Using the feature

1. Analyze the original email through the Gmail connector or upload its original `.eml`.
2. Open **View forensic report**, then **Attachment, QR and OCR analysis**.
3. Expand a PDF and select **Unlock and scan PDF**.
4. Enter the document password, give consent, and select **Unlock and analyse**. This is not your Gmail/banking login password. You may skip.
5. Read **Optional PDF content reviews**. A suspicious review also displays a warning above the original email score.

The backend retrieves the PDF from the preserved original: users do not need to upload the attachment again. If that original is unavailable, reanalyze the original email first. Reconstructed text-only analyses cannot supply missing attachments. Older report pages must be refreshed after deployment.

This first version supports PDF files, up to 10 MiB and the first five pages. ZIP and Office passwords are not supported. A document's password protection, financial subject, or verified sender is not evidence of either safety or malware.

## What is inspected

- PDF password authentication and native text extraction through pypdf, including AES-encrypted PDFs.
- Decrypted PDF object traversal for JavaScript, launch/form actions, remote actions and embedded content. These are review warnings, not proof of malware. No action or embedded file is executed.
- Page rendering through PDFium, followed by existing OCR and QR detection.
- Existing NETRA NLP, multilingual request-context checks and local email ML predictions over extracted text. The email model is supporting evidence; it has not been separately calibrated on PDF content. An ML label alone does not flag this review.
- Existing offline URL analysis over text URLs, URI annotations and decoded QR destinations. Live destinations are not visited and document URLs are not sent to external reputation services. Only hostnames, static scores and fixed finding titles are saved.
- The original encrypted attachment's hash is checked against the configured local malware blocklist, when available. This does not check hashes of embedded or decrypted files and is not a full antivirus scan.

The report distinguishes `suspicious`, `no_threats_detected`, `limited`, and `not_inspected`. A wrong password, worker failure, timeout or missing original never becomes a safe result. Per-page check coverage remains visible even when warnings were found. OCR language coverage and very small/blurred QR codes remain limitations.

## Data flow and authorization

The dashboard calls `POST /api/v2/emails/{email_id}/attachments/{sha256}/unlock` with JSON `{password, consent: true}`. It refuses non-local HTTP connections. Existing API authentication, role authorization and mutation rate limits apply. Analyst/admin roles can scan within the existing single-organization access model; auditors and extension submitters cannot invoke this operation. This is not multi-tenant ownership isolation.

The backend matches the hash to the recorded attachment, verifies that evidence belongs to the investigation, verifies the original email hash, then extracts the exact matching MIME part. No arbitrary replacement upload is accepted. Each result is appended to `attachment_reviews`, recording actor, consent, time, original attachment hash and check results. It does not overwrite the original email verdict or raw evidence. The dashboard and newly generated JSON/HTML/PDF case reports include the latest 20 reviews. The new review table is application-level audit history, not independently anchored tamper-proof storage.

## Password and content handling

Passwords travel through the dashboard server to the analysis backend, so this is server-assisted decryption, not client-only decryption. Passwords are passed to a one-shot worker through stdin pipes, not command arguments, environment variables or temporary task files. NETRA does not intentionally persist passwords or extracted document text in database records, logs, reports or browser local storage. The dialog clears on submission/close. Workers use in-memory PDF buffers; only the original encrypted evidence and reduced scan findings remain stored.

This does not guarantee cryptographic memory erasure: Python strings, operating-system swap/crash dumps and separately configured proxy/APM request-body logging need operator controls. Do not enable request-body capture on the unlock endpoint. Findings (including hostnames and actor) follow the deployment's investigation-retention policy; this change does not add an automatic deletion schedule.

## Isolation and deployment

- Native Render hosting selects the existing portable subprocess mode by default. It has a 35-second parent timeout, 30-second child alarm on supported platforms, two-worker concurrency limit, reduced environment, and POSIX CPU/memory limits. Python socket operations are blocked for PDF extraction. This is defense in depth, **not** OS-enforced isolation against a native PDF parser exploit. Windows lacks the POSIX resource limits.
- Docker mode supplies OS network isolation, a read-only filesystem, non-root user, dropped capabilities and resource limits. Explicit Docker failures never silently switch to portable mode.
- Root/backend/inspection dependency lists include pinned pypdf and pypdfium2 versions. Deploy both backend and dashboard. Native Render should install them through its normal build command.
- For Docker deployments, rebuild `docker build -f inspection/Dockerfile -t netra-inspector:4.6.0 .` and update any explicit `NETRA_INSPECTION_IMAGE` setting. An old worker image does not support unlocking.
- No new API key, service subscription or model retraining is needed. Existing local model artifacts must be provisioned; missing models are reported as unavailable.

## Validation

The full automated suite passed 289 tests (12 dependency deprecation warnings). Tests cover correct/wrong passwords, damaged files, page limits, PDF actions, original-email/hash binding, consent, roles, HTTPS enforcement, dialog behavior, append-only reviews and absence of passwords/plaintext in saved review data.

Run `python -m evaluation.encrypted_pdf_smoke` for five synthetic cases through the actual local portable worker and analyzers. Results are written to `evaluation_results/upgrades/encrypted_pdf_smoke.json`. The measured local Windows run passed all five: benign PDF, suspicious text/URL, QR destination, active JavaScript object, and wrong password. Successful scans took 5.518–15.319 seconds; wrong-password rejection took 0.533 seconds. These are functional smoke results, **not** real-world accuracy, recall, production latency or a load benchmark. Render and Docker execution were not validated by this local run.

## Code map

- `backend/pdf_inspection.py`: bounded decryption, extraction, rendering and static object inspection in workers.
- `backend/attachment_review.py`: original-evidence binding and privacy-reduced NLP/ML/URL review results.
- `backend/inspection_client.py`, `portable_inspection_worker.py`, `inspection_worker.py`: subprocess/container dispatch and password pipe handling.
- `backend/main.py`, `database.py`: authenticated route, persistence and report retrieval.
- `dashboard/attachment_review_ui.py`, `dashboard/app.py`, `dashboard/api_client.py`: consent dialog, HTTPS submission and plain-language findings.
- `backend/report_service.py`: supplemental findings in new exported case reports.
- `tests/test_pdf_unlock.py`, `evaluation/encrypted_pdf_smoke.py`: regression tests and reproducible synthetic smoke validation.
