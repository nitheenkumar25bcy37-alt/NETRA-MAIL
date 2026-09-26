"""Field-level network evidence; never guess hosting from an ASN holder."""
from datetime import datetime, timezone
from backend.intelligence.registration import enabled
from backend.intelligence.transport import transport, LookupError

FIELDS = ("country", "region", "city", "asn", "isp", "organization", "hosting_provider", "cloud_provider", "vpn", "proxy", "tor")


def enrich_network(result, client=None):
    from backend.intelligence.ip_provider import IPIntelligenceProvider
    client = client or transport
    result = dict(result)
    provenance = result.setdefault("field_provenance", {})
    for field in FIELDS:
        provenance.setdefault(field, [{"value": result.get(field), "source": result.get("source"),
            "looked_up_at": result.get("looked_up_at"), "status": "observed" if result.get(field) is not None else "unknown"}])
    result["network_enrichment"] = {"source": "RIPEstat prefix-overview", "status": "disabled"}
    if not enabled("NETRA_NETWORK_ENRICHMENT_ENABLED") or IPIntelligenceProvider._classify(str(result.get("ip", ""))) != "public":
        return result
    lookup = result["network_enrichment"]
    lookup["looked_up_at"] = datetime.now(timezone.utc).isoformat()
    try:
        data = client.get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": result["ip"]})
        lookup["retrieved_at"] = data.get("_netra_retrieved_at", lookup["looked_up_at"])
        rows = data["data"]["asns"]
        if data.get("status") != "ok" or not isinstance(rows, list):
            raise LookupError("malformed_response")
        lookup["announcing_networks"] = [{"asn": "AS" + str(int(row["asn"])), "holder": str(row.get("holder") or "")[:300]} for row in rows[:10]]
        lookup["status"] = "ok" if rows else "not_observed"
        lookup["data_time"] = data.get("data_call_time")
        for field, values in (("asn", [r["asn"] for r in lookup["announcing_networks"]]),
                              ("organization", [r["holder"] for r in lookup["announcing_networks"] if r["holder"]])):
            for value in values:
                provenance[field].append({"value": value, "source": lookup["source"], "looked_up_at": lookup["retrieved_at"], "status": "observed", "meaning": "BGP announcing network, not necessarily ISP or hosting provider"})
            distinct = {str(v).upper().removeprefix("AS") if field == "asn" else str(v).lower() for v in values + ([result[field]] if result.get(field) else [])}
            if len(distinct) > 1:
                lookup.setdefault("conflicting_fields", []).append(field)
            elif len(values) == 1 and result.get(field) is None:
                result[field] = values[0]
        result["available"] = result.get("available", False) or bool(rows)
    except (LookupError, TypeError, KeyError, ValueError, AttributeError) as exc:
        lookup["status"] = str(exc) if isinstance(exc, LookupError) else "malformed_response"
    return result
