# Mail infrastructure geolocation

NETRA extracts public IPs from original Received headers, orders observed mail-server hops, and enriches origin candidates with country, city, coordinates, ASN and network owner. These are infrastructure estimates, not the human sender location. Untrusted or forged lower headers can mislead attribution.

## Deployment
The default service is https://ipwho.is (HTTPS, basic lookup without a key). Set NETRA_IP_INTEL_URL=https://ipwho.is on the Render backend if an existing environment has an empty or incorrect value. Redeploy backend and dashboard. Blueprint deployments also include this setting in render.yaml.

Lookup requests share only the candidate public IP with the lookup provider, not message bodies, recipients or access tokens. Positive results are cached for one hour, failures briefly. Analysis enriches at most four unique IPs; the dashboard enriches at most eight candidates. The service can impose rate limits and has no guaranteed free-tier uptime. VPN/proxy/Tor flags remain unknown unless explicitly returned by a configured provider; geography alone does not increase the risk score.

An explicit empty NETRA_IP_INTEL_URL disables external lookups. A custom service must return the documented normalized geo/network fields as JSON at its base URL followed by /IP. ipwho.is connection fields are also supported.

## Missing information
No public IP: use Analyze current email with Gmail OAuth or upload an original .eml. Do not substitute a website DNS IP for the email sender. Private/reserved IPs are not geolocated. Provider/network errors show their status in the dashboard. Old reports without original headers require reanalysis. Saved available intelligence is used before live refresh.
