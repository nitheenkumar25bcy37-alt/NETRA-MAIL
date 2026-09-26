"""Bounded graph traversal over qualified weighted-correlation edges (not graph ML)."""
import networkx as nx
from email.utils import parseaddr
from urllib.parse import urlsplit


def qualified(relation, records):
    evidence = relation.get("evidence", [])
    fields = {v.get("field") for v in evidence}
    # Two independent, message-specific families and suspicious context required.
    # Provider IP/ASN, registrar, nameserver, geography and anonymisation never qualify.
    families = set()
    if fields & {"shared_sender", "shared_reply_to"}: families.add("address")
    if "shared_url" in fields: families.add("url")
    if "shared_attachment_hash" in fields: families.add("file")
    if fields & {"subject_similarity", "body_structure_similarity"}: families.add("content")
    ids = (relation.get("source_email_id"), relation.get("target_email_id"))
    return len(families) >= 2 and bool(families & {"url", "file"}) and all(
        records.get(i, {}).get("risk_score", 0) >= 35 for i in ids)


def build_graph(analysis, relationships, analyses=None):
    email_id = analysis["email_id"]
    records = {r["email_id"]: r for r in (analyses or []) if r["email_id"] != email_id}
    records = dict(list(records.items())[:99])
    records[email_id] = analysis
    nodes, edges, qualifying = {}, [], []
    campaign_graph = nx.Graph()
    campaign_graph.add_nodes_from(records)
    def node(kind, value):
        identifier = str(value) if kind == "email" else kind + ":" + str(value)
        nodes[identifier] = {"id": identifier, "type": kind, "label": str(value)[:2048]}
        return identifier
    def link(source, kind, value, relation, evidence=None):
        if value is not None and value != "":
            target = node(kind, value)
            edges.append({"source": source, "target": target, "type": relation, "evidence": evidence, "campaign_qualified": False})
            return target
    for identifier, record in records.items():
        node("email", identifier)
        parsed = record.get("parsed") or {}
        sender = parseaddr((parsed.get("metadata") or {}).get("from", ""))[1].lower()
        if sender:
            link(identifier, "sender", sender, "observed_sender")
            if "@" in sender: link(identifier, "domain", sender.rsplit("@", 1)[1], "sender_domain")
        urls = list(parsed.get("urls") or [])
        urls += [r.get("href") or r.get("normalized") for r in parsed.get("url_references", []) if isinstance(r, dict)]
        for url in list(dict.fromkeys(str(v) for v in urls if v))[:30]:
            try:
                host = urlsplit(url).hostname
                if host:
                    u = link(identifier, "url", url, "observed_url")
                    link(u, "domain", host.lower(), "url_host")
            except ValueError: pass
        for attachment in parsed.get("attachments", [])[:30]:
            link(identifier, "attachment_hash", attachment.get("sha256"), "contains_attachment")
        for item in parsed.get("ip_intelligence", [])[:8]:
            ip = link(identifier, "ip", item.get("ip"), "observed_public_infrastructure")
            if ip: link(ip, "asn", item.get("asn"), "network_announces_ip", item.get("field_provenance", {}).get("asn"))
        for candidate in (parsed.get("origin_trace") or {}).get("origin_candidates", [])[:8]:
            link(identifier, "ip", candidate.get("ip"), "origin_candidate", {"basis": candidate.get("basis"), "timestamp": candidate.get("timestamp")})
        for item in (parsed.get("domain_intelligence") or {}).get("domains", [])[:8]:
            domain = link(identifier, "domain", item.get("domain"), "observed_domain")
            reg = item.get("registration") or {}
            if domain:
                proof = {k: reg.get(k) for k in ("source", "status", "looked_up_at")}
                link(domain, "registrar", reg.get("registrar"), "registered_through", proof)
                for ns in reg.get("nameservers", [])[:10]: link(domain, "nameserver", ns, "registration_nameserver", proof)
                for ns in (item.get("records") or {}).get("NS", [])[:10]:
                    link(domain, "nameserver", ns, "dns_nameserver", {"source": item.get("lookup_source"), "looked_up_at": item.get("lookup_timestamp")})
        for obs in (parsed.get("infrastructure_reputation") or {}).get("observations", [])[:30]:
            observation_node = link(identifier, "reputation_indicator", obs.get("indicator"), "sourced_reputation_observation", obs)
            if observation_node:
                for kind in ("ip", "domain"):
                    target = kind + ":" + str(obs.get("indicator"))
                    if target in nodes:
                        edges.append({"source": observation_node, "target": target, "type": "exact_indicator_match", "evidence": obs, "campaign_qualified": False})
    seen_edges = set()
    for relation in relationships[:500]:
        a, b = relation["source_email_id"], relation["target_email_id"]
        if a not in records or b not in records:
            continue
        if (min(a,b), max(a,b)) in seen_edges: continue
        seen_edges.add((min(a,b), max(a,b)))
        node("email", a); node("email", b)
        ok = qualified(relation, records)
        edge = {"source": a, "target": b, "type": relation["relationship_type"], "evidence": relation.get("evidence", []), "confidence": relation.get("confidence"), "requires_review": True, "campaign_qualified": ok}
        edges.append(edge)
        if ok:
            campaign_graph.add_edge(a, b)
            qualifying.append(edge)
    distances = dict(nx.single_source_shortest_path_length(campaign_graph, email_id, cutoff=2))
    components = []
    for group in nx.connected_components(campaign_graph.subgraph(distances)):
        if len(group) > 1:
            components.append({"email_ids": sorted(group), "supporting_edges": [e for e in qualifying if e["source"] in group and e["target"] in group], "review_status": "candidate_requires_review"})
    return {"email_id": email_id, "nodes": list(nodes.values()), "edges": edges,
        "algorithm": "NetworkX two-hop breadth-first neighbourhood and connected components over qualified weighted evidence edges; no graph ML",
        "neighbourhood": distances, "candidate_clusters": components,
        "bounds": {"messages": 100, "relationships": 500, "hops": 2},
        "limitations": ["Requires two message-specific evidence families including exact URL or attachment hash, plus review-level risk on both messages.", "Common providers, ASN, registrar, nameserver, geography or VPN use cannot qualify a campaign edge.", "Bounded candidates can miss wider campaigns. A component is a review hypothesis, not common human ownership."]}


def graph_from_store(analysis, db):
    records = {analysis["email_id"]: analysis}; relations = []; frontier = [analysis["email_id"]]
    for _ in range(2):
        following = []
        for identifier in frontier[:50]:
            for relation in db.get_relationships(identifier)[:100]:
                if len(relations) >= 500: break
                relations.append(relation)
                for peer in (relation["source_email_id"], relation["target_email_id"]):
                    if peer not in records and len(records) < 100:
                        record = db.get_v2_analysis(peer)
                        if record:
                            records[peer] = record; following.append(peer)
        frontier = following
    return build_graph(analysis, relations, list(records.values()))
