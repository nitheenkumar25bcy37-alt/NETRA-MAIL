# Statement context and encrypted-PDF fixes — 4.8.1

## Evidence inspected

The user-linked hosted investigation showed 100/100 with passed SPF, DKIM,
DMARC and ARC. Contributions were link-display mismatches, credential/link
combination, multilingual urgency, BEC authority combination and urgency.
The link mismatch involved an opaque JioCX click route. A SEBI circular gained
URL-model points from payment-related path words. The PDF review history showed
one incorrect-password result followed by generic inspection failures.
No original private email, attachment or password is committed with this fix.

## Changes

- Require a positive payment request and authority language in the same passage
  for the BEC combination. Disclaimer words elsewhere do not qualify.
- Require a credential request, rather than any financial request elsewhere,
  for the credential-plus-link finding. Hindi verification terminology without
  a sensitive target no longer establishes a credential request.
- Recognize the exact HTTPS JioCX `/interface/ctr/v2/` opaque route as an
  unresolved tracking destination when trusted DMARC passes. This is a low
  uncertainty warning, not verified link safety. Lookalike hosts, unauthenticated
  senders, independent URL findings and reputation remain checked.
- URL-model support requires structural evidence beyond path keywords/length.
  This applies to all domains, not a bank or regulator allowlist.
- Preserve a bounded native PDF extraction checkpoint before optional visual
  processing. On timeout/native-worker failure, completed text, links and active
  object checks survive; missing OCR/QR remains explicitly unverified. Thread
  environment limits reduce worker resource contention. Existing process,
  input, memory and time limits remain in force.
- Retain sanitized scanner error codes and display specific failure explanations.
  Passwords and extracted document text remain excluded from saved review records.

Jio describes its transactional/promotional delivery and campaign tracking at
https://www.jio.com/business/services/cpaas/products/jiocx-email/ . The route
recognizer describes observed wrapper syntax; it neither visits recipient-specific
links nor claims to have verified their final destinations.

## Verification

- 343 Python tests passed, 12 warnings (41.29 seconds).
- Synthetic authenticated statement with opaque tracking: **12/100, low risk**.
  This is not a reanalysis of the user's original NSE message.
- Regression attacks cover credential pressure despite authenticated tracking,
  payment impersonation, tracker lookalikes and unverified sender authentication.
- A real local portable subprocess decrypted a synthetic AES-256 PDF with its
  correct test password and retained its native text. Wrong-password, malformed,
  partial visual failure and checkpoint recovery tests also pass.
- Existing 200-public-email offline corpus, threshold 35: 92 TP, 99 TN, 1 FP,
  8 FN, zero errors. Accuracy **95.5%**, precision **98.92%**, recall **92%**,
  F1 **95.34%**, false-positive rate **1%**. Previous recorded run: 95% accuracy,
  97.87% precision, 92% recall, 2% false-positive rate. This reused corpus is
  regression evidence, not new independent production validation.
- Results: `evaluation_results/upgrades/nse_fix_public_email.json`.

## Deployment acceptance still required

Deploy 4.8.1 to backend and dashboard, then reanalyse the selected Gmail message.
Historical investigations preserve their original scores. Retry the optional PDF
review on the new investigation. The exact private PDF and hosted resource failure
have not been reproduced locally; the previous report discarded the underlying
failure code. If it still fails, the new scanner status identifies the next action.
Neither a blue tick nor successful PDF decryption proves that content is safe.
