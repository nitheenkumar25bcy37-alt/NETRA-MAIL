from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dashboard.api_client import APIClient
from backend.presentation import explain_analysis


st.set_page_config(page_title="NETRA-Mail Investigation", page_icon="N", layout="wide")

def selected_api_client() -> APIClient:
    configured = APIClient()
    # Migrate dashboards that still have the retired Render API hostname in
    # their environment. Render preserves manually entered environment values
    # across deploys, so correcting render.yaml alone cannot update them.
    if configured.base_url == "https://netra-mail-api.onrender.com":
        configured = APIClient("https://netra-mail.onrender.com")
    requested = str(st.query_params.get("api_origin", "")).rstrip("/")
    allowed = {
        configured.base_url,
        "https://netra-mail.onrender.com",
    }
    allowed.update(
        origin.strip().rstrip("/")
        for origin in os.getenv("NETRA_ALLOWED_API_ORIGINS", "").split(",")
        if origin.strip()
    )
    if requested and requested in allowed:
        return APIClient(requested)
    return configured


client = selected_api_client()
st.markdown("""
<style>
:root { color-scheme: dark; }
.block-container { padding-top: 2rem; max-width: 1400px; }
[data-testid="stMetric"] { background: #172033; border: 1px solid #2a3a53; padding: 12px; }
</style>
""", unsafe_allow_html=True)


def safe_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs), None
    except Exception as exc:
        return None, str(exc)


def risk_color(score: int) -> str:
    return "#ef4444" if score >= 75 else "#f59e0b" if score >= 50 else "#22c55e"


def render_finding(finding: Dict[str, Any]):
    severity = str(finding.get("severity", "unknown")).upper()
    st.markdown(f"**{finding.get('title', 'Finding')}**  ·  `{severity}`  ·  confidence `{float(finding.get('confidence', 0)):.0%}`")
    st.write(finding.get("description", "No explanation available."))
    for key, value in (finding.get("evidence") or {}).items():
        if isinstance(value, (str, int, float, bool)):
            st.write(key.replace("_", " ").capitalize() + ": " + str(value))
        elif isinstance(value, list) and all(isinstance(item, (str, int, float)) for item in value):
            st.write(key.replace("_", " ").capitalize() + ": " + ", ".join(map(str, value)))
    with st.expander("Technical evidence and limitations"):
        st.json({"evidence": finding.get("evidence", {}), "limitations": finding.get("limitations", [])})


def render_overview():
    st.title("NETRA-Mail Investigation Platform")
    st.caption("Detect, explain, trace, correlate, preserve, report")
    summary, error = safe_call(client.summary)
    if error:
        st.error(f"Backend unavailable: {error}")
        st.info("Start the FastAPI backend and confirm the configured API URL.")
        return
    cols = st.columns(5)
    for column, label, value in zip(cols, ("Analyzed emails", "Critical", "High risk", "Open cases", "Suspected campaigns"), (summary.get("total_emails", 0), summary.get("critical_emails", 0), summary.get("high_risk_emails", 0), summary.get("open_cases", 0), summary.get("suspected_campaigns", 0))):
        column.metric(label, value)
    st.subheader("Provider and integrity status")
    st.json({"provider_status": summary.get("provider_status", {}), "integrity_warnings": summary.get("integrity_warnings", 0), "limitations": summary.get("limitations", [])})
    st.subheader("Recent analyses")
    data, error = safe_call(client.emails, 10, 0)
    if error:
        st.warning(error)
    else:
        for item in data.get("items", []):
            score = int(item.get("risk_score", 0))
            st.markdown(f"`{item.get('email_id')}`  **{item.get('classification', 'Unknown')}**  · score **{score}/100**")


def render_email(email_id: str):
    result, error = safe_call(client.email, email_id)
    if error:
        st.error(error)
        return
    findings, findings_error = safe_call(client.findings, email_id)
    trace, trace_error = safe_call(client.trace, email_id)
    relationships, relation_error = safe_call(client.relationships, email_id)
    st.title("Email Investigation")
    st.caption(email_id)
    score = int(result.get("risk_score", 0))
    view = result.get("explanation") or explain_analysis({**result, "findings": (findings or {}).get("findings", [])})
    st.subheader(f"{view['classification']} | {score}/100")
    st.info(view["summary"])
    c1, c2, c3 = st.columns(3)
    confidence = float(result.get("confidence") or 0)
    c1.metric("Observation confidence", f"{confidence:.0%}" if confidence else "Not estimated")
    c2.metric("Evidence hash", str(result.get("evidence", {}).get("sha256", "Unavailable"))[:18] + "...")
    c3.metric("Analysis version", result.get("evidence", {}).get("analysis_version", "Unknown"))
    st.caption(view["confidence_note"])
    tabs = st.tabs(["Why this result?", "Origin trace", "Relationships", "Limitations"])
    with tabs[0]:
        st.subheader("Why NETRA reached this result")
        if findings_error:
            st.warning("Some finding details could not be loaded: " + findings_error)
        if not view["reasons"]:
            st.write("No actionable warning was reported. The available content did not provide enough strong evidence for a phishing verdict.")
        for finding in view["reasons"]:
            render_finding(finding)
        st.subheader("Text and multilingual analysis")
        text = view["text_analysis"]
        st.write("Detected language: " + text["language"])
        st.write(text["summary"])
        for signal in text["signals"]:
            st.write(signal["label"] + ": " + ", ".join(signal["cues"]))
        st.subheader("Link analysis")
        st.write(view["url_analysis"]["summary"])
        for index, url in enumerate(view["url_analysis"]["urls"], 1):
            with st.expander(f"Link {index}: {url['assessment']} | {url['risk_score']}/100", expanded=url["risk_score"] >= 35):
                st.code(url["url"], language=None)
                st.write("Destination: " + (url["destination"] or "Not established"))
                for reason in url["reasons"]:
                    st.write("- " + reason)
                if not url["reasons"]:
                    st.write("No specific URL warning reported. This does not guarantee the destination is safe.")
                model = url["model"]
                st.caption("URL model: " + (str(model.get("classification", "Prediction available")) if model.get("available") else "Unavailable") + "; " + ("contributed with structural evidence" if model.get("used_in_score") else "did not contribute to URL score"))
        st.subheader("Sender identity checks")
        for item in view["authentication"]:
            with st.expander(f"{item['name']}: {item['status']} | {item['label']}"):
                st.write(item["meaning"])
                st.write(item["interpretation"])
                if item["reason"]:
                    st.write(item["reason"])
        st.subheader("Email machine-learning support")
        model = view["model"]
        st.write("Prediction: " + str(model.get("classification", "Not reported")) if model.get("available") else "Model evidence was unavailable for this analysis.")
        st.caption("Used with corroborating evidence." if model.get("used_in_decision") else "Did not contribute to the verdict. Model output alone does not establish phishing.")
        st.subheader("What should I do next?")
        for action in view["recommended_actions"]:
            st.write("- " + action)
        with st.expander("Technical data for analysts"):
            st.json({"analysis": result, "findings": findings})
    with tabs[1]:
        if trace_error:
            st.error(trace_error)
        else:
            hops = trace.get("hops", []) or []
            candidates = trace.get("origin_candidates", []) or []
            limitations = trace.get("limitations", []) or []

            if not hops:
                st.warning("Origin trace unavailable for this analysis")
                st.write(
                    "The captured Gmail message did not include the trusted Received "
                    "header chain needed to reconstruct mail-server hops. NETRA will not "
                    "invent an IP address or sender location."
                )
                st.caption(
                    "To populate this section, analyze the original .eml message with full "
                    "headers or use a trusted mail-provider/server-side ingestion source."
                )
            else:
                st.subheader("Observed mail-server hops")
                for index, hop in enumerate(hops, 1):
                    st.markdown(f"**Hop {index}**  `{hop.get('source_hostname') or 'Unknown'}` -> `{hop.get('destination_hostname') or 'Unknown'}`")
                    st.caption(f"IP: {hop.get('source_ip') or 'Unknown'} · classification: {', '.join(hop.get('ip_classifications', [])) or 'Unknown'} · timestamp: {hop.get('timestamp') or 'Unavailable'}")

                st.subheader("Origin candidates")
                if not candidates:
                    st.info("No defensible public origin candidate was present in the observed hops.")
                for candidate in candidates:
                    st.write(f"`{candidate.get('ip')}` · confidence `{float(candidate.get('confidence', 0)):.0%}` · {', '.join(candidate.get('basis', []))}")
            map_points = []
            for candidate in candidates:
                ip = str(candidate.get("ip") or "")
                if not ip:
                    continue
                intel, intel_error = safe_call(client.ip_intelligence, ip)
                if intel_error or not intel or not intel.get("available"):
                    continue
                st.caption(
                    f"Registered network: {intel.get('city') or 'Unknown'}, "
                    f"{intel.get('region') or intel.get('country') or 'Unknown'} | "
                    f"ASN: {intel.get('asn') or 'Unknown'} | "
                    f"Provider: {intel.get('organization') or intel.get('isp') or 'Unknown'}"
                )
                try:
                    latitude = float(intel.get("latitude"))
                    longitude = float(intel.get("longitude"))
                    if latitude or longitude:
                        map_points.append({"lat": latitude, "lon": longitude, "ip": ip})
                except (TypeError, ValueError):
                    pass
            if map_points:
                st.subheader("Origin infrastructure map")
                st.map(map_points, latitude="lat", longitude="lon", size=120)
            if candidates:
                st.info("Geolocation is infrastructure intelligence and does not prove the sender's physical location.")
            if limitations:
                with st.expander("Origin-trace limitations"):
                    for limitation in limitations:
                        st.write(f"- {limitation}")
    with tabs[2]:
        graph, graph_error = safe_call(client.graph, email_id)
        if graph and not graph_error:
            import json
            lines = ["digraph investigation {", "rankdir=LR;"]
            for node in graph.get("nodes", []):
                lines.append(f'{json.dumps(node["id"])} [label={json.dumps(node.get("label", node["id"]))}];')
            for edge in graph.get("edges", []):
                lines.append(f'{json.dumps(edge["source"])} -> {json.dumps(edge["target"])} [label={json.dumps(edge["type"])}];')
            lines.append("}")
            try:
                st.graphviz_chart("\n".join(lines))
            except ImportError:
                st.dataframe(graph.get("edges", []), use_container_width=True)
            st.caption("Relationships are investigative hypotheses; shared infrastructure does not establish human identity.")
        if relation_error:
            st.error(relation_error)
        elif not relationships.get("relationships"):
            st.info("No stored relationships for this email.")
        else:
            for relationship in relationships["relationships"]:
                st.markdown(f"**{relationship.get('relationship_type')}** · confidence `{float(relationship.get('confidence', 0)):.0%}`")
                st.json({"evidence": relationship.get("evidence", []), "limitations": relationship.get("limitations", [])})
    with tabs[3]:
        for limitation in result.get("limitations", ["Not enough evidence."]):
            st.write("- " + limitation)


def render_cases():
    st.title("Cases")
    with st.expander("Create case"):
        with st.form("create_case"):
            title = st.text_input("Title")
            description = st.text_area("Description")
            severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
            priority = st.selectbox("Priority", ["low", "normal", "high", "urgent"])
            if st.form_submit_button("Create case"):
                created, create_error = safe_call(client.create_case, {"title": title, "description": description, "severity": severity, "priority": priority})
                if create_error:
                    st.error(create_error)
                else:
                    st.success(f"Created {created.get('case_id')}")
    data, error = safe_call(client.cases)
    if error:
        st.error(error)
        return
    cases = data.get("cases", [])
    if not cases:
        st.info("No persisted cases.")
        return
    for case in cases:
        with st.expander(f"{case.get('case_id')} · {case.get('title')} · {case.get('status')} / {case.get('severity')}"):
            st.write(case.get("description", ""))
            st.json({"emails": case.get("email_ids", []), "campaigns": case.get("campaign_ids", []), "tags": case.get("tags", []), "notes": case.get("notes", [])})
            new_status = st.selectbox("Status", ["open", "investigating", "contained", "resolved", "closed", "false_positive"], index=["open", "investigating", "contained", "resolved", "closed", "false_positive"].index(case.get("status", "open")), key=f"status_{case['case_id']}")
            if st.button("Save status", key=f"save_{case['case_id']}"):
                updated, update_error = safe_call(client.update_case, case["case_id"], {"status": new_status})
                if update_error:
                    st.error(update_error)
                else:
                    st.success(f"Case updated to {updated.get('status')}")
            note = st.text_input("Add analyst note", key=f"note_{case['case_id']}")
            if st.button("Add note", key=f"add_note_{case['case_id']}") and note:
                _, note_error = safe_call(client.add_note, case["case_id"], note)
                st.error(note_error) if note_error else st.success("Note added")
            tag = st.text_input("Add tag", key=f"tag_{case['case_id']}")
            if st.button("Add tag", key=f"add_tag_{case['case_id']}") and tag:
                _, tag_error = safe_call(client.add_tag, case["case_id"], tag)
                st.error(tag_error) if tag_error else st.success("Tag added")
            evidence, evidence_error = safe_call(client.case_evidence, case["case_id"])
            if evidence_error:
                st.warning(evidence_error)
            else:
                st.subheader("Evidence")
                st.dataframe([{key: item.get(key) for key in ("evidence_id", "evidence_type", "filename", "sha256", "integrity_status")} for item in evidence.get("evidence", [])], use_container_width=True)
                for item in evidence.get("evidence", []):
                    if st.button(f"Verify {item.get('evidence_id')}", key=f"verify_{item.get('evidence_id')}"):
                        verification, verification_error = safe_call(client.evidence_verify, item["evidence_id"])
                        if verification_error:
                            st.error(verification_error)
                        else:
                            st.json(verification)
            timeline, timeline_error = safe_call(client.case_timeline, case["case_id"])
            if not timeline_error:
                st.subheader("Timeline")
                for event in timeline.get("timeline", []):
                    st.write(f"`{event.get('created_at')}` · {event.get('description')}")


def render_campaigns():
    st.title("Campaigns")
    data, error = safe_call(client.campaigns)
    if error:
        st.error(error)
        return
    campaigns = data.get("campaigns", [])
    for campaign in campaigns:
        with st.expander(f"{campaign.get('name')} · {campaign.get('status')} · {float(campaign.get('confidence', 0)):.0%}"):
            st.write(campaign.get("description", ""))
            st.write("Related email IDs:", ", ".join(campaign.get("email_ids", [])) or "Unavailable")
            st.caption("Campaign relationships show shared evidence and require analyst confirmation; they do not identify an attacker.")


def render_reports():
    st.title("Reports")
    case_id = st.text_input("Case ID")
    if not case_id:
        st.info("Enter a case ID to view and generate reports.")
        return
    reports, error = safe_call(client.reports, case_id)
    if error:
        st.error(error)
        return
    st.json(reports)
    format_choice = st.selectbox("Generate format", ["json", "html", "pdf"])
    if st.button("Generate report"):
        generated, generation_error = safe_call(client.create_report, case_id, format_choice)
        if generation_error:
            st.error(generation_error)
        else:
            st.success(f"Report created: {generated.get('report_id')}")
            st.json({key: generated.get(key) for key in ("report_id", "format", "evidence_count", "integrity_verified", "limitations")})


def main():
    requested_email_id = str(st.query_params.get("email_id", ""))
    if requested_email_id:
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            requested_email_id,
        ):
            st.error("The requested email investigation ID is invalid.")
            return
        st.sidebar.caption(f"API: {client.base_url}")
        st.sidebar.info("Opened from the Gmail risk badge")
        if st.sidebar.button("Back to overview"):
            st.query_params.clear()
            st.rerun()
        render_email(requested_email_id)
        return
    page = st.sidebar.radio("Navigate", ["Overview", "Email analysis", "Campaigns", "Cases", "Reports"])
    st.sidebar.caption(f"API: {client.base_url}")
    if page == "Overview":
        render_overview()
    elif page == "Email analysis":
        data, error = safe_call(client.emails, 100, 0)
        if error:
            st.error(error)
            return
        email_ids = [item.get("email_id") for item in data.get("items", [])]
        selected = st.selectbox("Select analyzed email", email_ids or ["No analyses available"])
        if email_ids:
            render_email(selected)
    elif page == "Campaigns":
        render_campaigns()
    elif page == "Cases":
        render_cases()
    else:
        render_reports()


if __name__ == "__main__":
    main()
