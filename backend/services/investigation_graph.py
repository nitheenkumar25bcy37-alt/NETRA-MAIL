from email.utils import parseaddr
from urllib.parse import urlsplit


def build_graph(analysis, relationships):
    email_id = analysis["email_id"]
    nodes = {email_id: {"id": email_id, "type": "email", "label": email_id}}
    edges = []
    parsed = analysis.get("parsed", {})
    domains = set()
    sender = parseaddr(parsed.get("metadata", {}).get("from", ""))[1]
    if "@" in sender:
        domains.add(sender.rsplit("@", 1)[1].lower())
    for url in parsed.get("urls", [])[:100]:
        try:
            host = urlsplit(str(url)).hostname
            if host:
                domains.add(host.lower())
        except ValueError:
            continue
    for domain in sorted(domains):
        identifier = "domain:" + domain
        nodes[identifier] = {"id": identifier, "type": "domain", "label": domain}
        edges.append({"source": email_id, "target": identifier, "type": "observed_domain"})
    for candidate in parsed.get("origin_trace", {}).get("origin_candidates", [])[:100]:
        if not candidate.get("ip"):
            continue
        identifier = "ip:" + candidate["ip"]
        nodes[identifier] = {"id": identifier, "type": "ip", "label": candidate["ip"]}
        edges.append({"source": email_id, "target": identifier, "type": "origin_candidate", "confidence": candidate.get("confidence"), "requires_review": True})
    for relation in relationships[:100]:
        source, target = relation["source_email_id"], relation["target_email_id"]
        for identifier in (source, target):
            nodes[identifier] = {"id": identifier, "type": "email", "label": identifier}
        edges.append({"source": source, "target": target, "type": relation["relationship_type"], "confidence": relation.get("confidence"), "requires_review": True})
    return {"email_id": email_id, "nodes": list(nodes.values()), "edges": edges, "limitations": ["Edges show observed indicators or review hypotheses, not common human ownership."]}
