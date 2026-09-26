# NETRA-Mail: SIH 26106 demonstration guide (4.8)

## Current claim

NETRA-Mail connects user-initiated email analysis to sourced infrastructure evidence, a qualified relationship graph and a preserved forensic report. It assists investigation; it does not prove human identity, guarantee safety or perform graph machine learning.

The current [implementation matrix](SIH_26106_IMPLEMENTATION_4_8.md) and [idea/abstract](SIH_26106_IDEA_ABSTRACT.md) supersede older feature and validation claims.

## Prepare the real demonstration

1. Deploy backend and dashboard from the same release. Confirm the backend readiness endpoint succeeds and the dashboard shows 4.8.0. Preserve the database and encrypted evidence storage across deployments.
2. Set the public enrichment flags in the configuration guide. Put the dashboard's analyst API credential only in its server environment. An extension submission credential cannot create cases or export analyst reports.
3. Load NETRA in Chrome and confirm the OAuth client's extension ID matches the installed extension. Enable Gmail API, configure Gmail read-only scope and add the demonstration account as a test user if the OAuth app is in testing.
4. Use a consented synthetic demo message in that account. Approve Google's consent prompt when selecting **Analyze current email**. An OAuth error is a failed live acceptance step, not something fixtures can verify away.
5. Confirm the extension and dashboard use the same API origin. The badge's dashboard URL must contain the returned `email_id` and matching `api_origin`.
6. For a campaign example, prepare two explicitly synthetic suspicious messages sharing an exact example URL or attachment hash plus a sender/content indicator. Do not use active phishing links or send unsolicited test emails. A normal bank notification should not be forced into a campaign. Cluster results must follow actual analysis evidence.

## Judge walkthrough: approximately three minutes

### 1. Gmail analysis: 40 seconds

Open the selected demo email. Click **Analyze current email**. Explain that the extension retrieves only the selected original through the backend after consent; it does not silently scan the mailbox. Show the badge, then select **View forensic report** to open that investigation in the dashboard.

### 2. Explain the result and infrastructure: 60 seconds

Show the reasons and distinguish model review recommendations from independently observed malicious indicators. Open **Origin trace**. Show returned country/region/city, ASN, network organisation, and their provider/lookup metadata. Say: "This is the observed mail-server infrastructure, not the person's physical address."

Show domain registration: queried domain, registrar, creation date, expiry and calculated age. Explain that these are registration records, separate from DNS records. If a provider omits a field or is unavailable, show the truthful status; do not fill it manually. A known registrar, old domain or Google brand check is not a blanket safety guarantee.

### 3. Evidence graph: 40 seconds

Open **Relationships**. Show sender, URL, attachment hash and infrastructure nodes. Open any qualifying candidate cluster and show the exact shared indicators. Explain that NetworkX bounded breadth-first traversal and connected components operate over qualified evidence edges; common ASN/registrar or VPN use alone cannot create a campaign. A single email may correctly have no candidate cluster.

### 4. Export and verify: 40 seconds

Expand **Export this investigation and its evidence graph**. Click **Prepare forensic PDF**, then **Download forensic PDF**. Open it and confirm the same email ID, registration/network evidence, graph edges, limitations and evidence integrity details. This action creates a case and links the preserved original; it uses the existing authenticated report API.

## Acceptance record — do not prefill success

For an actual hosted run, record the timestamp, backend/dashboard release, synthetic email ID, consent outcome, badge link, graph outcome, report ID and integrity result. Do not record mailbox tokens or passwords.

| Step | Acceptance criterion | Current evidence |
|---|---|---|
| Installed extension and Google consent | Real selected message returns an analysis ID | Pending live browser/account check |
| Extension handoff contract | Returned ID and originating backend build the dashboard link | JavaScript contract tests |
| Original analysis and preservation | API result survives storage and retrieval; original hash verifies | Synthetic integration test |
| Dashboard and graph | Same investigation shows enriched evidence and graph nodes without rendering error | Real Streamlit AppTest against local API with provider fixtures |
| Forensic PDF | UI export downloads a PDF containing the same investigation and evidence | Automated click, PDF text extraction and integrity check |
| RDAP/GeoIP/RIPE/Tor | Actual public provider responses | Live public acceptance JSON |
| Licensed WHOIS/ThreatFox | Permitted account returns usable data | Pending credentials/live verification |

**Automated evidence:** 333 Python tests and 7 extension contract tests passed. This is functional validation, not a new detection-accuracy benchmark. The 4.7 offline detection benchmark is documented separately and must not be described as production accuracy.

## If a demonstration step fails

- Missing investigation: check API-origin consistency and persistent storage, then reanalyse. Do not hide the missing-record state.
- Consent error: check OAuth extension ID, Gmail scope and test-user registration. Do not replace consent with a hardcoded token.
- Unknown registration/location: inspect the source status, quota and configuration. Continue showing the other evidence and label this lookup incomplete.
- No campaign cluster: this is expected without enough qualifying evidence. Show the observed graph without claiming a campaign.
- Report error: confirm the original evidence reference exists, the dashboard credential has analyst permission, and storage/encryption keys are available.
