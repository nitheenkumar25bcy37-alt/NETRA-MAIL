# Financial email false-positive fixes — 4.5.4

## What changed

NETRA previously combined ordinary delivery and marketing infrastructure with
financial vocabulary into a strong phishing verdict. The changes are general
rules, not exceptions for particular messages or a bank-name safety whitelist.

- HTML link labels now stop at the closing anchor. A later exchange disclaimer
  cannot become the displayed label of a preceding help link. Hidden text is
  excluded and nested formatting retained.
- Google redirect and Amazon SES click-tracking destinations are decoded with
  depth/size limits, without visiting the link. Nested `redirect_uri` links are
  inspected too; unknown wrapper hosts retain their own structural checks.
  Encoded targets are not claimed to be observed live redirects.
- Destination checks retain private-address, impersonation, homograph and
  reputation evidence. Optional isolated shortener expansion receives the
  decoded short URL. Unresolved shorteners produce an uncertainty finding,
  rather than proving phishing on their own. Network expansion remains opt-in.
- A DMARC result received directly from Gmail for the exact visible sender
  domain is retained separately from later local alignment. Missing local
  signing evidence cannot overwrite that receipt-time pass with a false fail.
  Uploaded EML authentication claims cannot activate this trusted boundary.
- An authenticated message can legitimately have a different envelope return
  path. Mail-server IPs are not expected to equal website A/AAAA addresses.
  These observations remain visible without misleading risk points.
- Lexical rules distinguish explicit safety advice and local PDF-opening
  instructions from requests to disclose credentials. High-risk request rules
  require an action and a sensitive target. The original text still feeds ML,
  forensic evidence and the independent content checks.
- Repeated rule contributions use the strongest severity, regardless of link
  order, so an earlier harmless link cannot conceal a later dangerous one.
- The dashboard separates sender authentication from content safety, explains
  score contributions and minimum-score rules, and shows decoded destinations.

These domain-relationship rules apply to authenticated organizations generally,
including banks not named in a special list. Existing configured aliases support
known cross-domain relationships. We do not claim an exhaustive or verified
catalog of every Indian bank. Groww is a financial platform, not treated as a
bank merely because it sends financial messages.

## Blue checkmark

Gmail's BIMI/VMC checkmark supports verified brand identity; it does not certify
every link or attachment as harmless. NETRA does not trust an icon embedded in
the message body or use a client-supplied badge boolean to bypass security.
The implemented trust evidence is server-verified/provider-sourced email
authentication. The UI does not claim that NETRA independently verified a VMC.

Sources: [Google BIMI](https://workspaceupdates.googleblog.com/2023/05/expanding-gmail-security-BIMI.html)
and [Amazon SES tracking](https://docs.aws.amazon.com/ses/latest/dg/faqs-metrics.html).

## Measured validation

Recorded locally on 25 September 2026, before (4.5.3) and after (4.5.4).

| Evaluation | Before | After |
| --- | --- | --- |
| Financial fixtures: false positives / 12 legitimate emails | 12/12 | 0/12 |
| Financial fixtures: detected / 8 attacks | 8/8 | 8/8 |
| Existing deterministic benchmark: false positives / 4 legitimate emails | 0/4 | 0/4 |
| Existing deterministic benchmark: detected / 16 attack-labeled emails | 15/16 | 15/16 |

The existing benchmark retains 93.75% recall and 96.77% F1 at its threshold of
25. The new financial matrix uses score >=35 or an attack classification as
its detection criterion. These thresholds differ, so do not combine results.
Both sets are small synthetic regression suites, not independent estimates of
production accuracy. Financial fixtures simulate trusted Gmail authentication
and disable DNS/reputation/fetches; parsing, ML and scoring use the real code.
The original private Groww email has not been replayed here, so its new exact
score is not asserted. Reanalyze it after deployment.

262 automated tests passed. A local Streamlit AppTest with a synthetic report
also rendered sender authentication, score contribution and decoded tracking
destination explanations without exceptions. This is not a hosted UI check.

Raw evidence is in `evaluation_results/upgrades/financial_mail_before.json`,
`financial_mail_after.json`, `financial_fix_baseline.json`, and
`financial_fix_after.json`.

Reproduce from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m evaluation.financial_mail_regression --output evaluation_results/upgrades/financial_mail_after.json
.\.venv\Scripts\python.exe -m evaluation.evaluate_v2 --output evaluation_results/upgrades/financial_fix_after.json
```

## Deployment and interpretation

Deploy both backend and dashboard at version 4.5.4. Existing reports are saved
historical results, not silently rewritten. Analyze the original Gmail email
again and confirm the new report's analysis version. No new API key or browser
permission is required for this release. The Gmail OAuth flow remains necessary
for trusted receipt-time authentication.

A low score can remain for uncertain links or other weak observations; it is
not a percentage probability of phishing. Use the finding explanations rather
than promising that authenticated or blue-checkmarked mail is definitely safe.
