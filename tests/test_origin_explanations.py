from backend.presentation import explain_origin, explain_analysis, explanation_lines

def trace(intel=None):
    return {"hops":[{"source_hostname":"mail.example"}],"origin_candidates":[{"ip":"8.8.8.8","intelligence":intel or {}}]}

def test_headers_absent_is_distinct_from_public_ip_absent():
    assert "headers were not captured" in explain_origin({})["title"]
    view=explain_origin({"hops":[{"extracted_ips":["10.0.0.1"]}]})
    assert "No public" in view["title"] and "Private/internal" in view["summary"]

def test_google_server_is_kept_without_claiming_sender_location():
    view=explain_origin(trace({"available":True,"organization":"Google LLC","city":"Example city","latitude":37,"longitude":-122}))
    server=view["servers"][0]
    assert server["ip"]=="8.8.8.8" and server["coordinates"]
    assert "Google" in server["explanation"] and "not established" in view["sender_location"]
    assert "user's own IP may not appear" in server["explanation"]

def test_vpn_exit_ip_is_kept_and_not_treated_as_human_location():
    server=explain_origin(trace({"available":True,"country":"Example country","vpn":True}))["servers"][0]
    assert "VPN" in server["anonymization"] and "does not reveal" in server["anonymization"]
    assert "or prove malicious activity" in server["anonymization"]

def test_lookup_failure_is_not_missing_ip():
    server=explain_origin(trace({"available":False,"source":"provider_unavailable"}))["servers"][0]
    assert "lookup unavailable" in server["status"]
    assert "does not mean the public IP is missing" in server["explanation"]

def test_rate_limits_and_disabled_lookups_have_actionable_reasons():
    assert "request limit" in explain_origin(trace({"source":"provider_rate_limited"}))["servers"][0]["explanation"]
    assert "turned off" in explain_origin(trace({"source":"unconfigured"}))["servers"][0]["explanation"]

def test_network_only_and_invalid_coordinates_do_not_make_map_markers():
    server=explain_origin(trace({"available":True,"organization":"Example network","latitude":float("nan"),"longitude":0}))["servers"][0]
    assert "location unknown" in server["status"] and server["coordinates"] is None
    assert not explain_origin({"hops":[{}],"origin_candidates":[{"ip":"10.0.0.1"}]})["servers"]

def test_unknown_vpn_flag_is_not_a_negative_result():
    assert "could not be established" in explain_origin(trace())["servers"][0]["anonymization"]

def test_report_contains_origin_explanation_and_keeps_risk_score():
    result={"risk_score":21,"classification":"Legitimate or low risk","parsed":{"origin_trace":trace({"available":True,"organization":"Google LLC","country":"Example country"})}}
    view=explain_analysis(result)
    lines="\n".join(explanation_lines(view))
    assert "Google" in lines and "Human sender location: not established" in lines
    assert result["risk_score"]==view["risk_score"]==21


def test_exported_forensic_report_includes_server_location_limits():
    from backend.report_service import ReportService
    result={"email_id":"test","risk_score":21,"classification":"Legitimate or low risk","parsed":{"origin_trace":trace({"available":True,"organization":"Google LLC","country":"Example country"})}}
    result["explanation"]=explain_analysis(result)
    report={"report_id":"test","case_id":"test","observed_evidence":{"emails":[result]},"evidence_count":0,"integrity_verified":False,"evidence_inventory":[],"limitations":[],"attribution_disclaimer":"Not human attribution"}
    html=ReportService._render(report,"html").decode()
    assert "Google LLC" in html and "Human sender location: not established" in html
    assert "Public mail-server IPs found" in html


def test_dashboard_access_error_is_separate_from_provider_failure():
    server=explain_origin(trace({"source":"dashboard_lookup_failed"}))["servers"][0]
    assert "data-access problem" in server["explanation"] and "not a missing public IP" in server["explanation"]
