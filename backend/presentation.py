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
    lines.extend(["Suggested next steps:", *view["recommended_actions"], "Assessment limitations:", *view["limitations"]])
    return lines
