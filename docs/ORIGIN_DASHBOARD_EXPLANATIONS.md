# Plain-language origin reports

The Origin trace tab explains mail-server evidence before showing analyst details. It distinguishes missing delivery headers, no extracted public IP, provider lookup failures, network-only information and approximate server locations. Public Gmail/cloud/VPN IPs are preserved. A location on the map identifies observed infrastructure, not the human sender. VPN use is shown only when reported by the provider; unknown information is not treated as a negative finding.

Shared explanations in backend/presentation.py feed API explanations, dashboard origin cards and exported forensic reports. dashboard/app.py enriches up to eight candidates, retains observed IPs when lookup fails, and displays validated coordinates. Analyst data remains available in an expandable section. Detection rules and risk scores are unchanged by this update. tests/test_origin_explanations.py verifies missing-data distinctions, Google infrastructure, VPN exits, provider errors, invalid coordinates, exported wording and score preservation.

## File integration
Only files contributing to this update are committed: presentation helper, dashboard integration, regression tests and this documentation. Existing detection/parser/auth/GeoIP modules remain active dependencies. Previously generated handbook files and local outputs are user artifacts and are left outside this commit. The superseded backend backup and tracked runtime GeoIP caches were removed in the preceding upgrade; source modules are not removed simply because they are optional or offline during benchmarking.

Verification: 27 targeted origin explanation, dashboard and report-export checks passed. Dashboard access failures are distinguished from IP-provider failures. Threat scoring was not modified; previous detection benchmark metrics are not remeasured or claimed as new results for this presentation change.
