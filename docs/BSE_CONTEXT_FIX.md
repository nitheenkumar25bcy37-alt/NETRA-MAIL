# Bilingual financial-message context — NETRA 4.5.5

## Diagnosis

The inspected BSE report used 4.5.4 and scored 54 from three text rules:
26.88 urgency/request points, 13.68 multilingual credential points and 12.96
multilingual financial points. Authentication passed. Links and attachments
did not contribute to that email score. The email model prediction was not used.

The old rules treated `password` and `KYC` as actionable multilingual findings,
and combined urgency anywhere in the message with a request elsewhere. The
local-document filter missed the multi-sentence instruction "You will be
prompted to enter a password" following instructions to open an attachment.

## Implementation

- English pressure and sensitive requests must occur in the same bounded
  passage. The triggering passage is redacted and included in evidence.
- Multilingual word matches without a related request are informational.
  Request evidence covers the supported native languages with explicit action
  patterns; keyword observations remain available for explanation.
- Local PDF/attachment-opening instructions use a short context window,
  including numbered lists. Online submission instructions and separate
  requests to send credentials are retained.
- The original text is preserved for ML and forensic analysis. This is a
  bounded heuristic improvement, not a claim of complete semantic understanding.
- The dashboard explains ordinary document context and displays matching
  passages for actionable rules. Brand authentication never bypasses dangerous
  URL, reputation or attachment findings.

## Attachment inspection

The live report showed `inspection_worker_unavailable`, which the Docker path
returns when its worker cannot run. It does not identify the precise daemon or
container failure. A live Render configuration change was not performed here.

When `NETRA_DEPLOYMENT_MODE=hosted` and no explicit inspection mode is supplied,
attachments now use the separate portable subprocess. Explicit
`NETRA_INSPECTION_MODE=docker` is respected and never silently downgraded after
failure. For native Render services set `NETRA_INSPECTION_MODE=portable`; this
is also the setting already present in render.yaml. Existing manually set
environment values may need correction in Render before redeployment.

Portable jobs now share the two-job capacity limit. They run outside the web
process with bounded inputs/time and a reduced environment, but are not a Docker
security boundary. URL network expansion retains its existing isolated path.

Unavailable attachment inspection displays **Not inspected**, not LOW 0/100.
PDFs receive **Limited inspection**: file properties were inspected but page
content was not fully decoded. An observed `/Encrypt` marker is recorded without
attempting decryption. The absence of that marker is not proof of an unencrypted
or safe PDF. Metadata warnings remain visible even when content is unavailable.

## Measured local results, 25 September 2026

| Suite | Before | After |
| --- | --- | --- |
| Bilingual/context fixtures: false positives / 4 legitimate | 3/4 | 0/4 |
| Bilingual/context fixtures: attacks detected / 4 | 4/4 | 4/4 |
| BSE-style synthetic fixture score | 54 | 10 |
| Existing deterministic set: attacks detected / 16 | 15/16 | 15/16 |
| Existing deterministic set: false positives / 4 | 0/4 | 0/4 |
| Prior financial suite: attacks detected / 8 | 8/8 | 8/8 |
| Prior financial suite: false positives / 12 | 0/12 | 0/12 |

Bilingual/context detection uses score >=25 or a non-low-risk classification;
the deterministic suite uses score >=25. The financial suite uses score >=35 or
a non-low-risk classification. Do not aggregate across these thresholds.
All are small synthetic development regressions, not independent production
precision/recall estimates. Authentication is simulated and network intelligence
disabled. The user's original private BSE MIME was not replayed; **10 is the
synthetic fixture result, not a promised score for the live message**.

277 tests passed. Native request tests cover Hindi, Tamil, Telugu, Kannada and
Malayalam. A real local portable subprocess returned limited PDF coverage, and
Streamlit AppTest verified the Not inspected label and context explanation.
Hosted execution is not established by these local checks.

Reproduce from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m evaluation.bse_context_regression --output evaluation_results/upgrades/bse_context_after.json
.\.venv\Scripts\python.exe -m evaluation.evaluate_v2 --output evaluation_results/upgrades/bse_after.json
.\.venv\Scripts\python.exe -m evaluation.financial_mail_regression --output evaluation_results/upgrades/bse_financial_after.json
```

Before/after JSON files are under `evaluation_results/upgrades/bse_*`.
The previous financial baseline is `financial_mail_after.json` from 4.5.4.
Deploy backend and dashboard, then analyze the original email again. Saved
historical reports retain their original scores and analysis version.
