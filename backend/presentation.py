"""Plain-language views of observed evidence; never changes a verdict."""
def _list(value):
    return [str(x)[:600] for x in value[:30] if isinstance(x, (str, int, float))] if isinstance(value, list) else []

def explain_analysis(result):
    parsed = result.get("parsed") or {}
    findings = result.get("findings") or []
    score = int(result.get("risk_score") or 0)
    reasons = [f for f in findings if f.get("severity", "info") != "info"]
    concerning = score >= 35 or any(f.get("severity") in {"medium", "high", "critical"} for f in reasons)
    nlp = parsed.get("nlp_analysis") or {}
    multi = parsed.get("multilingual_analysis") or {}
    labels = {"urgency": "Pressure to act quickly", "credential_harvesting": "Login, password or OTP-related language", "financial_fraud": "Payment or money-related language", "social_engineering": "Authority, secrecy or manipulation language"}
    categories = nlp.get("categories") or multi.get("multilingual_findings") or {}
    signals = [{"label": labels.get(k, k.replace("_", " ")), "cues": _list(v)} for k, v in categories.items() if _list(v)]
    if not signals:
        for f in findings:
            evidence = f.get("evidence") or {}
            for key in ("credential_cues", "financial_cues", "social_cues", "urgency_cues", "indicators"):
                if _list(evidence.get(key)):
                    signals.append({"label": f.get("title", "Text observation"), "cues": _list(evidence[key])})
    url_data = parsed.get("url_analysis") or {}
    urls = []
    for item in url_data.get("urls", []) or []:
        risk = int(item.get("risk_score") or 0)
        urls.append({"url": str(item.get("url") or item.get("href") or ""), "destination": str(item.get("redirect_target") or item.get("hostname") or item.get("registered_domain") or ""), "risk_score": risk, "assessment": "Suspicious characteristics found" if risk >= 35 else "No strong warning in this static URL check", "reasons": _list(item.get("risk_reasons")), "model": item.get("ml_analysis") or {}})
    auth_labels = {"spf": ("Sending-server authorization", "Was the sending server authorized for the envelope domain?"), "dkim": ("Signed-message integrity", "Does the original signed message match the signing-domain key?"), "dmarc": ("Visible-sender alignment", "Does verified SPF or DKIM align with the visible From domain?"), "arc": ("Forwarding-chain verification", "Is the signed authentication handover chain valid?")}
    authentication = []
    auth = parsed.get("verified_authentication") or {}
    for key, (label, meaning) in auth_labels.items():
        item = auth.get(key) or {}
        status = str(item.get("status") or "unavailable")
        interpretation = {"pass": "This identity or integrity check passed. It does not prove safe intent.", "fail": "This check failed. Review the reason and other evidence; failure alone is not proof of phishing."}.get(status, "No reliable pass or fail was established. Missing evidence is not an authentication failure.")
        if status == "unsigned":
            interpretation = "The original message contains no DKIM signature. An unsigned message is not automatically phishing."
        elif status == "none" and key == "arc":
            interpretation = "No ARC forwarding chain is present; ARC is not required for every email."
        authentication.append({"source": str(item.get("source") or "unavailable"), "receiver_status": item.get("receiver_status"), "receiver_source": item.get("receiver_source") or ("trusted_receiver" if item.get("receiver_status") and auth.get("delivery_source") == "gmail" else None), "name": key.upper(), "label": label, "meaning": meaning, "status": status, "interpretation": interpretation, "reason": str(item.get("reason") or "")})
    return {
        "classification": str(result.get("classification") or "Assessment unavailable"), "risk_score": score,
        "summary": "NETRA found evidence that needs attention. Review the reasons before clicking links, sharing information or sending money." if concerning else "NETRA did not find enough strong evidence to classify this email as phishing in the information it received. This does not guarantee that the email is safe.",
        "confidence_note": "No finding-based confidence estimate is available. A displayed 0% does not mean 0% chance of phishing." if not result.get("confidence") else "Confidence describes the observations, not a calibrated probability that the email is safe or malicious.",
        "reasons": reasons,
        "text_analysis": {"language": str(nlp.get("language") or multi.get("language") or "Not established"), "signals": signals, "summary": "These words are contextual clues. Ordinary payment or login language does not prove phishing." if signals else "No matching language cues were reported." if nlp or multi else "Detailed text output is unavailable in this older record. Reanalyze to capture it."},
        "url_analysis": {"urls": urls, "summary": f"{len(urls)} link(s) inspected. Link risk is separate from the overall email score." if urls else "No links were extracted from the captured content." if url_data else "Detailed URL output is unavailable in this record; this does not prove that it contains no links."},
        "authentication": authentication, "model": parsed.get("ml_analysis") or {},
        "origin": explain_origin(parsed.get("origin_trace") or {}),
        "recommended_actions": ["Avoid email links for login or OTP submission.", "Verify payment or account changes through a known phone number or official website.", "Preserve the original message and request security review."] if concerning else ["Confirm the sender and expected context before acting.", "Visit the official website directly for sensitive actions.", "Provide the original .eml for full header and attachment checks."],
        "limitations": _list(result.get("limitations")),
    }

def explanation_lines(view):
    lines = [f"Assessment: {view['classification']} | Email risk: {view['risk_score']}/100", view["summary"], view["confidence_note"], "Why NETRA reached this assessment:"]
    for reason in view["reasons"]:
        lines.append(f"{reason.get('title', 'Observation')} ({reason.get('severity', 'unknown')}): {reason.get('description', '')}")
        for key, value in (reason.get("evidence") or {}).items():
            if isinstance(value, (str, int, float, bool)):
                lines.append(f"Observed {key.replace('_', ' ')}: {value}")
            elif _list(value):
                lines.append(f"Observed {key.replace('_', ' ')}: {', '.join(_list(value))}")
    if not view["reasons"]:
        lines.append("No actionable findings were reported. Missing checks may still limit the assessment.")
    text = view["text_analysis"]
    lines.extend(["Text and multilingual analysis:", f"Language: {text['language']}", text["summary"]])
    for signal in text["signals"]:
        lines.append(f"{signal['label']}: {', '.join(signal['cues'])}")
    lines.extend(["Link analysis:", view["url_analysis"]["summary"]])
    for url in view["url_analysis"]["urls"]:
        lines.extend([f"Link: {url['url']}", f"Destination: {url['destination'] or 'Not established'}", f"URL risk: {url['risk_score']}/100 - {url['assessment']}", *(url["reasons"] or ["No specific URL warnings reported; destination safety is not guaranteed."])])
        model = url["model"]
        if model.get("available"):
            lines.append(f"URL model: {model.get('classification', 'Prediction available')}; {'contributed with structural evidence' if model.get('used_in_score') else 'did not contribute to URL score'}.")
    lines.append("Sender authentication:")
    for item in view["authentication"]:
        lines.extend([f"{item['name']} - {item['label']}: {item['status']}", item["meaning"], item["interpretation"]])
        lines.append("Evidence source: " + item["source"])
        if item.get("receiver_status"):
            lines.append("Delivery-provider result: " + str(item["receiver_status"]) + " (separate from current local verification)")
        if item["reason"]:
            lines.append(item["reason"])
    model = view["model"]
    lines.append("Email machine-learning support:")
    lines.append(f"Prediction: {model.get('classification', 'Not reported')}; {'used with corroborating evidence' if model.get('used_in_decision') else 'did not contribute to verdict'}." if model.get("available") else "Email model evidence unavailable. This is not a safe verdict.")
    origin = view.get("origin")
    if origin:
        lines.extend(["Where did this email travel from?", origin["title"], origin["summary"], origin["sender_location"], origin["next_step"]])
        for server in origin["servers"]:
            lines.extend([f"Observed server IP: {server['ip']}", server["status"], server["explanation"], server["location"], server["network"], server["anonymization"]])
    lines.extend(["Suggested next steps:", *view["recommended_actions"], "Assessment limitations:", *view["limitations"]])
    return lines


def explain_origin(trace):
    """Describe observed server evidence without inferring a person's location."""
    import ipaddress
    import math
    hops = trace.get("hops") or []
    servers = []
    seen = set()
    for candidate in trace.get("origin_candidates") or []:
        ip = str(candidate.get("ip") or "")
        try:
            if not ipaddress.ip_address(ip).is_global or ip in seen:
                continue
        except ValueError:
            continue
        seen.add(ip)
        intel = candidate.get("intelligence") or {}
        owner = str(intel.get("organization") or intel.get("isp") or "")
        location_parts = list(dict.fromkeys(str(intel[k]) for k in ("city", "region", "country") if intel.get(k)))
        coordinates = None
        if intel.get("available"):
            try:
                lat, lon = float(intel.get("latitude")), float(intel.get("longitude"))
                if math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180:
                    coordinates = {"lat": lat, "lon": lon, "ip": ip}
            except (TypeError, ValueError):
                pass
        if not intel.get("available"):
            status = "Server IP found; location lookup unavailable"
            explanation = {
                "unconfigured": "Location lookups are turned off or not configured for this deployment.",
                "provider_rate_limited": "The location service has reached its request limit. Try again later.",
                "provider_unavailable": "The location service could not return usable information. This does not mean the public IP is missing.",
                "lookup_budget": "This server was not looked up because the analysis reached its lookup limit.",
                "offline": "External location lookups were disabled for this offline analysis.",
                "dashboard_lookup_failed": "The dashboard could not retrieve location information from NETRA. This is a data-access problem, not a missing public IP. Ask your administrator to check dashboard connectivity and access.",
            }.get(intel.get("source"), "NETRA found a public server IP, but has no usable location-service result for it.")
        elif location_parts or coordinates:
            status = "Approximate mail-server location available"
            explanation = "This location describes the observed network or mail server, not the person who wrote the email."
            if not coordinates:
                explanation += " No usable map coordinates were returned, so NETRA cannot place a map marker."
        else:
            status = "Server network information available; location unknown"
            explanation = "The lookup returned network information but no usable location or map coordinates."
        if "google" in owner.lower():
            explanation += " The lookup identifies a Google network. For mail sent through Gmail, this can be Google's sending infrastructure; the user's own IP may not appear in the email."
        reported = [label for flag, label in (("vpn", "VPN"), ("proxy", "proxy"), ("tor", "Tor")) if intel.get(flag) is True]
        anonymization = "The provider reports " + ", ".join(reported) + " infrastructure. Its exit-server location does not reveal the user's original location or prove malicious activity." if reported else "VPN, proxy or Tor use could not be established from the available information. A VPN used to access Gmail may not appear in the email headers."
        if not reported and all(intel.get(flag) is False for flag in ("vpn", "proxy", "tor")):
            anonymization = "The provider did not flag this server as VPN, proxy or Tor infrastructure. This does not rule out a hidden VPN on the user's connection."
        servers.append({"ip": ip, "status": status, "explanation": explanation,
                        "location": "Approximate server location: " + (", ".join(location_parts) or "Not established"),
                        "network": "Network operator: " + (owner or "Not established"),
                        "anonymization": anonymization, "coordinates": coordinates})
    if servers:
        title = "Public mail-server IPs found"
        summary = "NETRA keeps observed public IPs even when they belong to Gmail, a cloud service or a VPN. NETRA starts with the oldest visible public hop; incomplete or forged headers can mislead the trace. These are clues about email delivery, not proof of the sender's identity."
        next_step = "Compare this route with sender identity checks and the email's text, links and attachments. An unfamiliar country alone does not make an email phishing."
    elif hops:
        title = "No public mail-server IP found in the captured headers"
        summary = "Delivery records were captured, but NETRA could not extract a public server IP from them. Private/internal addresses cannot be used for public geolocation. This is missing origin evidence, not proof that the email is safe."
        next_step = "Use Gmail original-message verification or upload the original .eml with full headers. Some providers still do not expose the user's IP."
    else:
        title = "Email delivery headers were not captured"
        summary = "NETRA has no mail-server route to inspect in this record. It cannot invent an IP address or map location."
        next_step = "Analyze the original email through Gmail verification or upload its original .eml file; reanalyze older records to capture their delivery headers."
    return {"title": title, "summary": summary, "servers": servers, "next_step": next_step,
            "sender_location": "Human sender location: not established. Headers may expose only mail servers or a VPN exit server. NETRA continues checking text, links, attachments and sender authentication when origin evidence is missing."}
