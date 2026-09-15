"""Portable report; untrusted message paths are HTML-escaped."""
from html import escape


def render_report(report):
    def cell(value):
        return escape(str(value))
    metrics = ["total", "errors", "tp", "tn", "fp", "fn", "precision", "recall", "f1",
        "false_positive_rate", "end_to_end_correct_fraction", "latency_p95_seconds"]
    summary = "".join(f"<tr><th>{cell(key)}</th><td>{cell(report.get(key))}</td></tr>" for key in metrics)
    rows = "".join("<tr>" + "".join(f"<td>{cell(row.get(key, ''))}</td>" for key in
        ["path", "expected", "predicted", "risk_score", "error"]) + "</tr>" for row in report["rows"])
    return ("<!doctype html><html lang='en'><meta charset='utf-8'><title>NETRA evaluation</title>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px}"
        "table{border-collapse:collapse;width:100%;margin:20px 0}td,th{border:1px solid #ccc;padding:8px;text-align:left}</style>"
        "<h1>NETRA evaluation</h1><p>" + cell(report["scope"]) + "</p><p>Threshold: " + cell(report["threshold"]) +
        "</p><table>" + summary + "</table><h2>Message results</h2><table><tr><th>File</th><th>Expected threat</th>"
        "<th>Predicted threat</th><th>Risk score</th><th>Error</th></tr>" + rows +
        "</table><p>" + cell(" ".join(report["limitations"])) + "</p></html>")
