# IP geolocation in NETRA 4.5.3

Set `NETRA_IPSTACK_API_KEY` on the **netra-mail backend** in Render's
Environment settings, then save and redeploy. Never put it in the Chrome
extension, dashboard URL, Git repository or report. The dashboard calls NETRA;
only NETRA calls ipstack over HTTPS. An explicit provider endpoint passed by
tests continues to override ipstack. Without a key, the existing IP provider
configuration continues to apply.

Local launch with `scripts/start_local.py` also reads an optional ignored
`.local-secrets/ipstack-key` file. Environment configuration takes precedence.

Analyze an email through Gmail original-message verification, then open the
forensic report's Origin trace tab. NETRA extracts the public delivery IP from
the selected trusted Gmail Authentication-Results SPF segment when present.
Uploaded authentication claims never receive this trusted status. Received
relay candidates continue to work and are labeled separately.

The dashboard shows the IP, approximate city/region/country, a map when valid
coordinates exist, provider, lookup timestamp and source of header evidence.
Missing connection/security fields remain unknown. Google/cloud/VPN servers
are retained as delivery infrastructure; a human sender's location is not
established. Different databases may place the same IP in different cities.
Country and network location alone are not proof of phishing.

Only public IPs are submitted to ipstack. No email body, attachment, mailbox
address or Gmail token is sent. Positive results are cached for one hour;
failures for 30 seconds in memory. Analysis makes at most four distinct relay
lookups; repeated dashboard requests use the existing cache. Keep track of the
account allowance: a small free quota can be exhausted by multiple unique IPs.
Provider errors distinguish invalid keys, quota exhaustion and unsupported plans.
Provider response bodies and credential-bearing request URLs are not returned
in errors or reports. No HTTP fallback or cross-host redirect is allowed.

Existing saved reports remain historical records. Reanalyze to capture newly
extracted SPF evidence. Render secrets are not supplied by a Git push; existing
services must have the environment variable entered separately.

Live acceptance on 2026-09-25: the supplied key successfully returned Germany,
Gunzenhausen for 195.201.243.180. Network and security modules were absent in
that response, so VPN, ISP and ASN must not be claimed from this lookup.

Validation: 241 automated tests passed before the final malformed-provider-response guard; focused origin/provider checks were rerun after that guard. A synthetic original-message fixture exercised the real ipstack provider and produced a valid map point; Streamlit AppTest rendered that result without exceptions. Hosted Gmail download and Render activation require the backend secret to be configured.
