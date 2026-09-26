# NETRA-Mail 4.8: infrastructure intelligence and demonstration acceptance

## Implemented / partial / blocked matrix

| Feature | Implementation | Deterministic verification | Live verification |
|---|---|---|---|
| RDAP registration, registrar, creation/expiry, status, nameservers, age | Implemented in existing domain provider; offline registry suffix parsing; IANA bootstrap | Success, missing/invalid/future date, redaction, bad response, unavailable, quota, unsupported domain | Passed on `example.com`; registry returned dates and registrar. Other TLDs remain provider-dependent |
| HTTPS WHOIS fallback | Implemented for unsupported/not-found RDAP, only with a licensed WhoisXML API key | Normalized date, missing date, metadata and secret protection; shared HTTP error tests | **Pending account/credential verification**; not represented as live-tested |
| Geo/network fields and provenance | Existing IP provider extended with RIPEstat BGP network lookup; keep country/region/city/ASN/ISP/organisation/hosting distinct | Missing fields, conflicting owners/ASN, invalid data, private IP filtering, bounds and cache | ipwho.is location and RIPEstat network check passed for `8.8.8.8`; no hosting provider inferred |
| Graph operations | Weighted matching retained; typed evidence nodes, NetworkX two-hop BFS and connected components of qualified relationships | Exact evidence, two-hop limit, common-cloud/registrar/NS over-linking, campaign persistence | Exercised through local API and actual Streamlit renderer; hosted deployment acceptance pending |
| VPN/proxy classification | Existing provider classifications preserved with provenance and freshness; informational only | True/unknown flags and no risk solely from VPN/geography/hosting | Paid security fields not live-verified; unavailable fields remain unknown |
| Timestamped Tor observations | Tor Project `exit-addresses`, bounded bulk retrieval, per-IP observation time | Parsing, stale observations, outages and no-match unknown state | Live list retrieval/parsing passed; public test IP need not be a Tor match |
| Botnet-related IP/domain reputation | ThreatFox exact IP/domain adapter; preserves IOC threat type and malware label; analyst observation only | Fixture match, expiry, quota/credential/outage handling and metadata-only disclosure | **Pending permitted account/Auth-Key**; no behavioural botnet detector claimed |
| Gmail → persisted analysis → API → dashboard → graph → PDF | Existing Gmail selected-original route, evidence linking and reports; added direct PDF export in investigation | Gmail-fetch fixture through real analysis/storage/API, Streamlit AppTest export click, PDF text and evidence-integrity assertions; extension JS contract tested separately | **Actual Google consent, installed Chrome extension and hosted run pending**. Fixtures are not live acceptance |

No model retraining or new accuracy improvement is claimed in this release. Earlier 4.7 benchmark results retain their original version and offline scope.

## What changed in the working pipeline

- `backend/intelligence/registration.py`: registration metadata, not DNS or sender identity. Queries the ICANN registrable domain (e.g. `company.co.uk`; a hosted tenant's registration may belong to its platform). Age is elapsed days from a valid, non-future registration date only. Redacted/missing dates produce unknown age. Reports retain the queried registration domain so its age is not misattributed to a tenant.
- `backend/intelligence/network_enrichment.py`: adds RIPEstat BGP announcing ASN/holder when usable; keeps competing values in field provenance and marks conflict. A holder is not automatically an ISP, host or human sender. Missing hosting-provider evidence remains unknown.
- `backend/intelligence/infrastructure_reputation.py`: current provider VPN/proxy/Tor observations plus optional Tor and ThreatFox records. No new reputation observation alone changes the risk verdict. Existing independent threat checks continue.
- `backend/intelligence/transport.py`: HTTPS only, redirects disabled, public destination validation, 2 MiB response ceiling, connect/read and streaming time bounds, bounded in-memory cache and negative cache. No exception text containing credentials is returned. Provider destinations are fixed or drawn from IANA bootstrap, never email-supplied lookup URLs.
- Existing domain/IP/orchestrator paths persist enrichment inside the analysis JSON. The existing email API explanation exposes a shared human-readable infrastructure view. Dashboard and HTML/PDF/JSON reports use the same stored evidence.
- `backend/services/investigation_graph.py`: sender-address, URL, domain, public IP, attachment SHA-256, ASN, registrar, DNS/registration nameserver and reputation nodes. Source/timestamps travel on enrichment edges. A reputation indicator connects to its exact IP/domain node, and email nodes connect its co-observed URLs/attachments. This is explainable graph traversal, **not graph ML**.
- `backend/services/campaign_service.py`: retains weighted indicator evidence but requires graph qualification before automatic campaign membership. Candidate comparison is bounded to the latest 200 analyses. Old saved campaigns remain historical records requiring review; they are not silently deleted or retroactively confirmed.
- `backend/report_service.py`: fixes missing analysis content when a new case links evidence without an explicit legacy `email_ids` list. Reports include graph evidence and all new infrastructure observations.
- `dashboard/app.py`: readable registration/network/reputation sections, cluster evidence and an in-investigation **Prepare forensic PDF** → **Download forensic PDF** flow.

## Qualification and freshness rules

An automatic campaign edge needs at least two independent message-specific families (sender/Reply-To, exact URL, attachment hash, subject/body structure), including an exact URL or attachment hash, and risk >=35 on both emails. Shared mail providers, relay IPs, ASN, registrar, nameservers, geography or VPN use cannot qualify an edge. A qualified component still requires analyst review and does not establish common human ownership. Neighbourhood traversal is limited to two hops, 100 messages and 500 relationships, so wider campaigns can be missed.

Reputation results retain source, retrieval/check time, observation time, expiry/freshness, evidence and `needs_review`. Local conservative freshness policies: VPN/proxy provider observation 1 hour; Tor exit observation 24 hours; ThreatFox last-seen (or first-seen if absent) 30 days. These windows are NETRA policies, not guarantees supplied by the sources. Expired/unknown observations are retained and labelled; they do not become current accusations. Email `Date` is sender-supplied, so overlap is context, not authenticated historical proof. Feed absence never means safe. ThreatFox infrastructure association is not proof that the sender operates a botnet and is not traffic/behaviour analysis.

## Configuration

New lookups default off in local environments. The Render blueprint enables the three public services; existing Render services may require these values to be added manually and redeployed.

Install the updated `requirements.txt` before starting a local backend; it pins NetworkX 3.5 for graph traversal. Render's existing build command installs this dependency automatically.

```text
NETRA_REGISTRATION_ENABLED=true
NETRA_NETWORK_ENRICHMENT_ENABLED=true
NETRA_TOR_ENABLED=true

# Only enable after obtaining a permitted account/key:
NETRA_THREATFOX_ENABLED=true
NETRA_THREATFOX_AUTH_KEY=<server-side secret>

# Optional licensed WHOIS fallback when RDAP is unsupported/not found:
NETRA_WHOISXML_API_KEY=<server-side secret>
```

Keep existing `NETRA_IPSTACK_API_KEY` or `NETRA_IP_INTEL_URL=https://ipwho.is` configuration. Provider plan limitations remain visible. Keep hosted authentication, analyst dashboard credentials, evidence encryption and persistent storage enabled. Never place these provider keys in the extension, Git or client-side UI. There is no purchase or account creation in this change.

RDAP discloses only the registrable domain; RIPE and GeoIP receive public IPs; ThreatFox receives at most six public IP/domain indicators per analysis, with an additional 12-second loop budget. Tor uses a bulk feed and receives no per-email indicator query. Email text, attachments, passwords and mailbox tokens are never sent to these enrichment services. Existing original-message access remains only between NETRA and the selected mailbox provider after user consent. No original message is used by the public live check script.

Cache policy: new JSON lookups typically 1 hour, IANA bootstrap 24 hours, Tor/ThreatFox 15 minutes, unsuccessful requests 60 seconds; maximum 512 transport entries. Domain provider additionally caches its combined result for five minutes. Returned metadata distinguishes lookup from cached retrieval time for RDAP/RIPE. An unavailable service does not stop email analysis. WHOIS fallback does not bypass an RDAP quota or permission error.

## Verification performed

- **333 Python tests passed, 12 warnings** in the final recorded suite. New tests use synthetic provider fixtures; routine tests disable external new enrichment by default.
- **7 extension JavaScript contract tests passed**, including Google consent request, selected message ID submission, same-origin dashboard handoff, redirect rejection and credential scoping.
- `tests/test_enrichment_workflow.py` exercises the real mailbox-analysis route with a synthetic original-message fetch, persists the evidence, requests the API, executes the Streamlit app, clicks PDF preparation and reads the PDF. This found and verified the case-link/report fix.
- Live public source evidence is in `evaluation_results/upgrades/infrastructure_live_acceptance.json`. It records RDAP, ipwho.is, RIPEstat and Tor status and timestamps. The source file is not a screenshot or fixture.

Reproduce from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --disable-warnings
node --test tests/extension_security.test.cjs
.\.venv\Scripts\python.exe -m scripts.check_public_enrichment
```

The final command makes real public-provider requests using only `example.com` and `8.8.8.8`. Provider availability may change. It deliberately does not exercise a paid fallback or Gmail login. Use the [demo guide](SIH_26106_FINALIST_DEMO.md) for hosted acceptance; record success only after actually completing those steps.

## Provider references

- [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) supplies registry endpoints.
- [WhoisXML request documentation](https://whois.whoisxmlapi.com/documentation/making-requests) specifies its authenticated HTTPS interface.
- [RIPEstat prefix overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview) supplies announcing ASN and holder, not a guaranteed hosting provider.
- [Tor Project exit observations](https://check.torproject.org/exit-addresses) supply timestamped observed exit addresses.
- [ThreatFox community API](https://threatfox.abuse.ch/api/) describes exact IOC search and Auth-Key requirements. Obtain access permitted for the intended deployment; source availability and terms are external dependencies.
