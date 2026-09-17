# Registered-domain link-label comparison

## Root cause
The previous rule treated any different hostname as a high-risk visible-link mismatch. The reported link displayed equery.irctc.co.in but opened www.irctc.co.in/nget/train-search. Both share irctc.co.in; that difference alone is not evidence of deception.

## General correction
backend/domain_identity.py canonicalizes hostnames with IDNA and uses tldextract's bundled Public Suffix List, with private suffixes enabled and HTTP fetching disabled. backend/url_analyzer.py treats sibling subdomains as an informational difference, not a high-risk deceptive mismatch. Unrelated registered domains, lookalikes, IP changes and separate hosted tenants retain the warning. Unknown suffixes receive no guessed shared-domain exemption. There is no IRCTC whitelist or sender/domain exception.

The URL still undergoes all other checks; shared domain does not prove safety or verified ownership. backend/presentation.py and dashboard/app.py explain this distinction in link cards and exported reports. Existing stored findings remain historical snapshots; reanalyze the email after backend redeployment to obtain the corrected finding.

Production installs the pinned dependency through requirements.txt. requirements-submission.lock records the additional installed dependencies. The offline suffix snapshot changes through deliberate package upgrades, so its coverage can age.

Reference: [tldextract project documentation](https://pypi.org/project/tldextract/).

## Verification
Full regression suite: 220 tests passed (11 dependency deprecation warnings), including sibling-subdomain, deceptive lookalike, private-hosting tenant, Unicode normalization, report explanation and full-email pipeline cases.
