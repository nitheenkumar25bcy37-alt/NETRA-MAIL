# Short URL expansion

The full email orchestrator expands known shorteners before extracting features from the final destination, and preserves original URL, redirect chain and any failure in parsed.url_expansions. It limits expansion to two links per message.

Enable NETRA_EXPAND_SHORT_URLS=1 only where the constrained Docker inspection worker is provisioned. The fetcher validates every redirect, rejects internal/reserved IPs, pins DNS resolution to checked public addresses, validates TLS, bounds redirects/time and performs HEAD requests without downloading pages. Disabled or unavailable workers produce an explicit unavailable result; NETRA does not pretend it inspected the destination. The ordinary Render Python runtime does not provide a Docker daemon, so this feature needs a worker-capable deployment. No unsafe in-process fallback was added.

Subdomain abuse already checks brand/account terms appearing outside the registered domain. IDN normalization now uses a curated confusable skeleton to detect protected-brand resemblance; ordinary internationalized names alone no longer trigger the generic high-severity finding. Coverage is bounded, not complete Unicode homograph detection.
