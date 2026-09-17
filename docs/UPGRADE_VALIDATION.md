# NETRA 4.5.0 upgrade evidence

## Summary
The student is the sole project contributor; the sir supplied the brief. The new full-email benchmark materially improves reliability. The old URL-only recall weakness remains: it has not been solved by these changes and must not be replaced with an unrelated model score in a presentation.

## Measured email pipeline results
200 held-out raw emails: 100 phishing from Nazario 2025 and 100 legitimate from Apache SpamAssassin easy-ham. An additional 200 messages form a calibration/development split. Message hashes are disjoint; template, sender and model-training independence are not established. SpamAssassin 2003 ham versus 2025 phishing creates substantial source/time shift. This is a public full-email pipeline benchmark, not proof of current institutional accuracy.

Threshold fixed at risk >=35; external DNS, DKIM DNS, ARC, URL reputation and expansion disabled. Originals are parsed, text/URL/attachments/header analysis run, and the composite risk score is evaluated. Persistence, Gmail OAuth, dashboard HTTP and live provider services are outside this benchmark.

| Phase | Precision | Recall | F1 | False positives | Processing errors |
|---|---:|---:|---:|---:|---:|
| Baseline 4.4.1 |72.83%|67.00%|69.79%|29.07%|14/200|
| Structural/auth-trust + phrases + homographs |62.22%|56.00%|58.95%|34.00%|0/200|
| Calibrated inconclusive ML review |68.14%|77.00%|72.30%|36.00%|0/200|
| Weaker infrastructure/forwarding weights |93.51%|72.00%|81.36%|5.00%|0/200|
| Sender-brand candidate (plain-only calibration) |93.59%|73.00%|82.02%|5.00%|0/200|
| Final production-aligned calibration |92.41%|73.00%|81.56%|6.00%|0/200|

Final confusion matrix: TP73/TN94/FP6/FN27; accuracy83.5%. The baseline FPR denominator excludes 14 processing errors; the final run includes all 100 ham. See common_case_email.json for the matched successfully processed cases. Errors are not silently counted as safe. Threshold35 existed before calibration; the ML review threshold .60 was chosen on development data, not the held-out test. Multiple measured stages on this same test set make it a monitored engineering benchmark; a new independently collected untouched corpus is required for a final generalization claim.

The 20 synthetic regressions remain 95% accuracy, 93.75% recall and 0 false positives before/after. This small synthetic result is not real-world accuracy.

## Calibration
Existing TF-IDF/logistic-regression base model was not retrained. Platt scaling fit on 200 development emails, activated after improvement on an internal validation split. Final ML test Brier error .23047 -> .18286; log loss .65397 -> .55320. Calibration and inference share the same subject/from/plain/visible-HTML text construction; optional image OCR is excluded from calibration. Calibration is bound to the base artifact SHA-256 and rejects invalid/stale parameters. Overall observation confidence remains a finding-confidence estimate, not calibrated probability of safety.

## URL measurement and rejected candidate
The existing 10,000-URL protocol measured baseline precision89.43%, recall41.78%, FPR4.94%; final precision89.54%, recall41.76%, FPR4.88%. Its best threshold10 was selected on the tested sample, so this historical protocol is diagnostic. A separate domain-group threshold-validation comparison is in threshold_holdout_url.json: baseline recall42.284%, final42.261%, effectively unchanged. Model training overlap is not excluded.

A model-only URL review candidate was rejected on development data: 93% recall but95% FPR. It was removed before final testing. Do not claim the stored URL model's historical97% result is the deployed full-email accuracy. Unknown URLs still rely on structural/domain/text evidence and optional maintained reputation. Compromised legitimate sites and structurally ordinary malicious URLs remain difficult without live evidence.

## Changes and status
1. **Escalation implemented:** verified SPF/DKIM/DMARC failure plus independent sender impersonation/homograph floors risk at75. Critical executable or configured blocked-hash attachment floors at75. Fired rules and reasons persist in parsed.risk_decision and appear in the dashboard. Untrusted uploaded authentication claims cannot trigger hard escalation.
2. **Recall signals:** curated character-TF-IDF phrase similarity added with request/context gates, negation handling and PII-redacted matched evidence; brand homograph normalization added. Subdomain abuse and pre-feature shortener expansion were already present and now have explicit scope and integration regression coverage. Shortener expansion needs a provisioned isolated worker and NETRA_EXPAND_SHORT_URLS=1; it was not measured as live functionality on Render.
3. **Calibration implemented:** artifact-bound Platt step feeds ML supporting/review decisions. Strong structural evidence takes priority; inconclusive calibrated model results request review rather than claiming confirmed phishing.
4. **Auth hardened:** existing SHA-256 API identities, role authorization and owner isolation retained; all authenticated mutation requests are centrally rate-limited once. The forgeable origin-only reconstructed-email shortcut was removed. Keyless original-Gmail submissions still require endpoint validation of a short-lived Google token and server-side Gmail original fetch before persistence. Other mutation routes require configured API credentials. Local loopback operator mode is explicitly separate; hosted mode fails closed without configuration. Verified tests cover401 missing credentials,429 rate limit,403/404 authorization/isolation. No new duplicate JWT layer was added.
5. **Public email benchmark implemented:** reproducible source download, bounded archive reading without path extraction, exact-hash deduplication, manifest validation and provenance hashes; raw corpus excluded from git.
6. **Correlation naming corrected:** weighted shared-indicator campaign correlation with investigation graph visualization. No graph ML or graph-traversal clustering claim. See CORRELATION_SCOPE.md.
7. **Attachment reputation wired:** local SHA-256 blocklist applies to worker and fallback/cached static outputs and creates an explicit blocked-hash finding. Configure NETRA_ATTACHMENT_BLOCKLIST with a JSON array of vetted hashes; no malware reputation feed is provisioned by default and no VirusTotal lookup is claimed. Known/unknown hash behavior is regression-tested.
8. **Concurrent pipeline measurement implemented:** 100 emails,10 threads. Final post-fix run0 errors, throughput9.09 emails/s, p50 .66s,p95 3.21s,p99 3.94s;4 attachment inspections skipped at worker capacity. Initial run1 error and two retries0; a later instrumented cold-start run captured1 sklearn module-import deadlock. The fix eagerly imports model dependencies before serving concurrent requests; the post-fix100-message run and a fresh-process20-message regression succeeded. Earlier load measurements and the captured failure are retained. Robustness under sustained production load remains unproven. This is local offline pipeline throughput, not hosted API/Gmail/provider scale.
9. **Privacy policy documented:** PRIVACY_RETENTION_POLICY.md maps controls and operator duties to the DPDP framework; it does not certify compliance or pretend scheduled erasure exists.
10. **External anchor tooling implemented and tested:** minimal HMAC-signed HTTPS checkpoint with durable receipt contract. Requires a separately operated store, configured endpoint/signing key and operator scheduling. A verified local legacy-chain release checkpoint is included in ledger_checkpoint.json; its containing GitHub commit is one external anchor after push. It does not cover Render's database or separate custody chains. No periodic external HTTPS store is configured; local receipts alone do not make the ledger independently tamper-evident.
11. **Ownership documented:** TEAM_CONTRIBUTIONS.md records sole-student ownership, teacher brief and AI coding assistance.

## Verification and reproduction
Final Python suite:197 tests verified. Transactional IRCTC and promotional email regressions retained. Main checks cover verified-vs-reported auth, dangerous attachments, homographs, sender-brand mismatches, calibrated/inconclusive model decisions, phrase negation, extension origin spoofing, rate limits, stale calibration and safe shortener integration.

From project root:
```powershell
.\.venv\Scripts\python.exe -m evaluation.run_release_validation --public-corpus
```
This runs regressions, synthetic emails, public emails and100-message concurrent measurement. New installations download the public corpus; benchmark network intelligence remains disabled. Calibration is provisioned in data/email_probability_calibration.json; refitting it deliberately uses `python -m evaluation.calibrate_email_model`. Comparison of historical URL scores needs the local before/after CSV artifacts generated by evaluate_netra.run_url_benchmark(); compact measured JSON summaries are versioned, duplicate raw reports are not.

Read scope and denominators in each report before quoting metrics. Production rollout still needs live authenticated HTTP load testing, worker provisioning, updated independently collected email validation, provider configuration and operator privacy/retention processes.
