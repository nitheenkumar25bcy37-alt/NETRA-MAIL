# Transactional email, attachment, QR and OCR correction

## What was wrong

1. URLs inside image, font, CSS and tracking-pixel resources were entering the clickable-link analyzer. Long encoded marketing URLs could therefore add risk even though the user could not click them.
2. Ordinary transactional nouns such as `transaction`, `password-protected`, `account` and `verification` could combine with a moderate ML probability and push an otherwise authenticated message into review.
3. The Gmail extension required non-empty body text. An open message containing only an attachment was rejected before the backend could fetch its original MIME.
4. The hosted Render service has no Docker daemon. Its Docker-only attachment worker could report inspection unavailable, so QR and OCR processing did not run reliably in the deployed service.
5. The dashboard did not state, in one place, whether each file was inspected, whether QR targets were decoded, or whether OCR ran.

## General correction (no bank or sender allowlist)

- The parser now analyzes visible body URLs and anchor destinations. Passive HTML resources remain recorded as HTML/image metadata but do not count as clicked links.
- Raw language categories remain evidence for unauthenticated messages. When Gmail supplies trusted authentication, DMARC passes and no structural URL, attachment, sender or BEC warning exists, ordinary transactional nouns do not add risk by themselves.
- Display-name checks now recognize when the claimed brand token is present in the sender's own domain label. This removes dependence on an incomplete list of official domains; trusted transactional handling still requires Gmail authentication, and confusable-character, deceptive-domain and modifier checks still run.
- A moderate calibrated ML output is shown as a low-level observation in that authenticated transactional context. It cannot force the score to the review threshold without technical evidence.
- Direct link-label deception, confusable IDNs and unsafe internal destinations still force review. The sibling-subdomain correction remains active.
- The extension can select an open Gmail message with an empty body. Gmail OAuth supplies the original message, including attachments.
- Render uses a restricted portable subprocess for static attachment inspection. The subprocess has an input limit, timeout, reduced environment and resource limits. It never executes attachment content.

No Groww, SBI, HDFC, NSE or other company was added to a safe list. The regression cases use fictional and real-format domains only to reproduce message structure; the production decision uses authentication and evidence quality.

## What the attachment features actually do

### Attachment analyzer

- Calculates SHA-256.
- Compares filename extension, MIME declaration and magic bytes.
- Detects executable/script types, double extensions, macro-enabled Office files, HTML/SVG and archives.
- Inspects ZIP/OOXML members under size, member-count and compression-ratio limits.
- Checks the optional local malware-hash blocklist.
- Never opens or executes a file as an application.

### QR analyzer

- Runs on supported raster-image MIME attachments.
- Decodes normal, rotated and moderately noisy QR images.
- Sends decoded HTTP(S) targets through the same URL analyzer used for clickable links.
- A QR code by itself is a review clue, not proof of phishing; the decoded destination determines the stronger evidence.

### OCR analyzer

- Runs bounded OCR on supported raster images.
- Adds extracted words to NLP/ML analysis so text embedded in an image cannot bypass language checks.
- Stores a hash and character count, and shows only a redacted preview in the dashboard.
- Does not currently decrypt password-protected PDFs or perform full PDF page rendering. Such a file is reported with the exact inspection limitation; it is never silently declared safe.

## Dashboard output

For every MIME attachment, the report now shows:

- filename, MIME type and byte size;
- `Static content inspection completed` or `Content inspection unavailable`;
- static attachment score and reasons;
- decoded QR target(s), if any;
- whether OCR ran and found readable text;
- a redacted OCR preview; and
- inspection limitations.

## Measured verification

- Complete automated suite: **231 tests passed** after the final change.
- Focused transactional/attachment suite includes Groww-style contract notes, a generic authenticated bank validation message, NSE-style trade mail, an SBI-style statement, attachment-only Gmail selection, tracking-resource exclusion, portable PDF/image inspection, QR decoding, OCR reporting and deceptive-link escalation.
- Public historical email benchmark (200 samples, offline, threshold 35): **92.31% precision, 72% recall, 80.90% F1, 6% false-positive rate, 83% accuracy, 0 processing errors**.
- Previous measured public result: 92.41% precision, 73% recall, 81.56% F1, 6% false-positive rate, 83.5% accuracy. The one-point recall change comes from excluding passive HTML resources as clickable evidence. This benchmark lacks trusted Gmail receiver context, so it does not measure the new authenticated-transactional suppression directly.
- Synthetic security regression: **100% precision, 93.75% recall, 96.77% F1, 0% false-positive rate, 95% accuracy, 0 errors**.

These corpora are engineering evaluations, not a production-accuracy guarantee.

## Deployment and retest

Render redeploys the backend and dashboard from Git. Reload extension version 3.4.3 in Chrome. Existing investigations are immutable historical results; open each test email and select **Analyze current email** again to create a result with analysis version 4.5.1.
