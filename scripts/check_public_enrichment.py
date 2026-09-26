"""Opt-in live acceptance using public infrastructure, never mailbox content.

Run from the repository root: python -m scripts.check_public_enrichment
Paid WHOIS/ThreatFox and Gmail consent are deliberately not exercised here.
"""
import json
import os
from pathlib import Path
from datetime import datetime, timezone


def main():
    os.environ.update(NETRA_REGISTRATION_ENABLED="true", NETRA_NETWORK_ENRICHMENT_ENABLED="true",
                      NETRA_TOR_ENABLED="true", NETRA_THREATFOX_ENABLED="false")
    from backend.intelligence.registration import RegistrationProvider
    from backend.intelligence.ip_provider import IPIntelligenceProvider
    from backend.intelligence.infrastructure_reputation import InfrastructureReputation
    result = {"scope": "Live public-infrastructure checks only; no mailbox data submitted",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "registration": RegistrationProvider().lookup("example.com"),
        "network": IPIntelligenceProvider(endpoint="https://ipwho.is").lookup("8.8.8.8"),
        "tor": InfrastructureReputation().lookup({"ip_intelligence": [{"ip": "8.8.8.8"}]}),
        "pending": ["Licensed WHOIS fallback", "ThreatFox credential/account verification", "Actual Gmail consent and installed extension on hosted deployment"]}
    destination = Path("evaluation_results/upgrades/infrastructure_live_acceptance.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"registration": result["registration"]["status"],
        "geo_source": result["network"]["source"], "location_available": result["network"].get("location_available", False),
        "network": result["network"]["network_enrichment"]["status"], "feeds": result["tor"]["lookups"]}, indent=2))


if __name__ == "__main__":
    main()
