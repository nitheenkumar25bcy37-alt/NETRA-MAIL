# Detection reliability: NETRA-Mail 4.7.0

## Measured result

These are **offline email review-detection results at risk score >=35**. A positive includes an inconclusive review recommendation, not only a confirmed-phishing verdict. The threshold is the same before and after. Errors: zero in every run.

| Test set | Emails | Before accuracy | After accuracy | After precision | After recall | After F1 | After false-positive rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| Original, previously reused | 200 | 76.5% | 97.5% | 98.97% | 96% | 97.46% | 1% |
| Additional audit, inspected during development | 200 | 71.5% | 90.5% | 98.80% | 82% | 89.62% | 1% |
| Final reserved audit, scored after model freeze | 200 | 72.5% | 95% | 97.87% | 92% | 94.85% | 2% |
| All three sets combined | 600 | 73.5% | **94.33%** | **98.54%** | **90%** | **94.08%** | **1.33%** |

Combined confusion matrix: TP 270, TN 296, FP 4, FN 30. Baseline: TP 160, TN 281, FP 19, FN 140. Final reserved audit: TP 92, TN 98, FP 2, FN 8. Do not substitute the original 97.5% for independent validation. The combined result includes development-informed test sets and is descriptive, not an unbiased estimate of deployment accuracy.

The current baseline is lower than the older slide's 83% because it was rerun after subsequent conservative scoring changes. First two baseline reports use 4.6.0; the final baseline uses 4.7.0 with the new model explicitly disabled, preserving the legacy scoring path.

## Gap and architecture change

The legacy classifier's bundled training CSV contained only 15 examples. Its conservative calibrated vote missed many attack-like messages. Version 4.7 adds a provisioned word-and-character logistic model for inconclusive cases:

1. Extract subject, plain text, visible HTML text and available attachment OCR. Exclude sender/Received/date headers from model features. Normalize Unicode, contact addresses, domains and numeric tokens to reduce source-specific shortcuts.
2. Use two fixed-size hashed feature spaces: word 1–2 grams and character 3–5 grams. Train logistic regression on 200 public development emails plus 40 explicitly synthetic contrasts between ordinary notices and harmful requests.
3. Select the 0.55 decision threshold using five-fold grouped public-development predictions under a 3% development false-positive budget. Synthetic contrasts appear only on the training side of each fold. There are 197 public template groups; development TP/TN/FP/FN are 97/97/3/3. This is development performance, not held-out accuracy.
4. Replace legacy classifier votes when the new artifact is available, preventing double counting. Require enough text or corroborating context. Authenticated transactional context without structural warnings suppresses this model-only promotion. No bank-name whitelist is introduced.
5. A model-only positive sets a review floor of 35 and remains **Suspicious but inconclusive**. Negative predictions cannot erase independent authentication, malicious URL or attachment findings. Decision scores are not calibrated probabilities of harm.
6. Store bounded gzip JSON numeric coefficients with a SHA-256 manifest, not executable pickle. Load once through a cache; never train in a request. Invalid/missing/disabled artifacts fall back to the existing classifier. API readiness and dashboard explanations report model availability and whether its vote contributed.

The dashboard and forensic explanation retain the model result and review gate. Existing QR, OCR, encrypted-PDF and malicious attachment rules remain separate evidence paths.

## Evaluation provenance and limits

Public sources are [Nazario phishing 2025](https://monkey.org/~jose/phishing/phishing-2025) and [SpamAssassin easy ham](https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2). Their different source and time distributions are a major limitation. These runs do not establish modern Indian-bank, multilingual or production accuracy.

All 600 test-message hashes are mutually disjoint and excluded from the 200 public training hashes. Additional audits exclude first-80-normalized-token matches and five-word-shingle similarity >=0.8 to previous messages, including within each new audit. This approximate filter cannot guarantee semantic independence. Audit preparation refuses to overwrite a frozen manifest. Raw public emails stay outside Git; provenance, hashes and per-message predictions are committed.

The first candidate scored 99% on the reused original set but failed ordinary-notification regression checks. It was rejected. Its `candidate_ungated` reports are retained for transparency and are not release metrics. Forty synthetic contrasts and contextual gating were subsequently added. No test emails were used to fit model weights. The first two test sets informed development; the final 200 were reserved until the candidate was frozen and no further score tuning followed.

The evaluator disables external reputation, URL expansion, IP/domain network intelligence and live DKIM/ARC verification. Attachment inspection depends on local worker availability; these scores do not certify successful OCR/QR/decryption coverage. Timings in raw reports were not an isolated load test and should not be presented as production latency.

## Reproduce and operate

From the repository root, using the existing local corpus manifests:

```powershell
.\.venv\Scripts\python.exe -m evaluation.train_content_model
.\.venv\Scripts\python.exe -m evaluation.evaluate_v2 --manifest .local-corpora/test.json --threshold 35 --output evaluation_results/upgrades/reliability_after.json
.\.venv\Scripts\python.exe -m evaluation.evaluate_v2 --manifest .local-corpora/reliability-audit/test.json --threshold 35 --output evaluation_results/upgrades/reliability_audit_after.json
.\.venv\Scripts\python.exe -m evaluation.evaluate_v2 --manifest .local-corpora/reliability-final-audit/test.json --threshold 35 --output evaluation_results/upgrades/reliability_final_audit_after.json
.\.venv\Scripts\python.exe -m evaluation.summarize_reliability
.\.venv\Scripts\python.exe -m pytest -q --disable-warnings
```

The release model is already bundled; production does not need corpus files or training. `evaluation/prepare_reliability_audit.py` and its `--final` option create audits only when no frozen manifest exists. Preserve existing manifests instead of resampling for a better score.

Set `NETRA_CONTENT_MODEL_ENABLED=false` to restore legacy classifier votes. `NETRA_CONTENT_MODEL_PATH` optionally points to another artifact with its matching `.manifest.json`. Regression validation for this release: **296 passed, 12 warnings**. The summary JSON records model/report hashes and aggregates every reported final split rather than selecting only the best score.
