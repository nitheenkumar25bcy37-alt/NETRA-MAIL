#!/usr/bin/env python3
"""Generate and evaluate 25 reproducible emails, including five novel phishing sites."""
from __future__ import annotations

import argparse
import csv
import html
import json
import random
import statistics
import string
import sys
import time
from email.message import EmailMessage
from pathlib import Path


SEED = 20260916
PHISHING_THRESHOLD = 35


SAFE_TOPICS = [
    ("Project planning", "The project planning meeting is scheduled for {day} at {hour}:00.", "https://docs.python.org/3/"),
    ("University lecture", "The network security lecture begins at {hour}:00 in room {number}.", "https://en.wikipedia.org/wiki/Computer_security"),
    ("Internship update", "Your internship orientation is confirmed for {day}. Please review the schedule.", "https://internshala.com/student/dashboard"),
    ("Travel itinerary", "Your approved travel itinerary reference {reference} is attached for review.", "https://www.google.com/travel/"),
    ("Birthday invitation", "You are invited to a birthday dinner on {day} at {hour}:00.", ""),
    ("Team stand-up", "Tomorrow's team stand-up will cover sprint progress and blockers.", "https://github.com/openai/openai-python"),
    ("Quarterly report", "The quarterly report is ready for review before the finance meeting.", ""),
    ("Payment receipt", "Your payment receipt {reference} has been recorded successfully. No action is required.", ""),
    ("Bank statement", "Your monthly bank statement is available in the official mobile application.", ""),
    ("Security training", "Mandatory security awareness training starts on {day}. Never share your password.", "https://www.microsoft.com/en-us/security"),
    ("Password policy", "The IT team published updated password guidance. Contact the help desk with questions.", ""),
    ("Conference registration", "Your conference registration {reference} is confirmed for {day}.", ""),
    ("Medical appointment", "Your clinic appointment is confirmed for {day} at {hour}:00.", ""),
    ("Library reminder", "The borrowed book is due next week. Renew it through the library portal.", ""),
    ("Delivery update", "Your office equipment delivery is expected on {day} between 10:00 and 12:00.", ""),
    ("Workshop feedback", "Thank you for attending the workshop. Please share your feedback.", ""),
    ("Code review", "Pull request {reference} is ready for code review by the engineering team.", "https://github.com/python/cpython"),
    ("Event agenda", "The community event agenda includes registration, talks and lunch.", ""),
    ("Leave approval", "Your leave request {reference} has been approved by your manager.", ""),
    ("Invoice review", "The supplier invoice {reference} was received and will be reviewed this week.", ""),
]


PHISHING_TEMPLATES = [
    ("PayPal account warning", "Your PayPal account is suspended. Login and verify your password immediately at {url}"),
    ("Bank KYC expiry", "Urgent: your bank KYC expires today. Confirm account details and OTP at {url}"),
    ("Microsoft password notice", "Your Microsoft password expires now. Sign in and authenticate at {url}"),
    ("Confidential invoice", "CEO confidential request: open the payment portal and process the wire transfer at {url}"),
    ("Hindi account warning", "तुरंत अपना पासवर्ड सत्यापित करें और यहाँ क्लिक करें; खाता निलंबित होगा। {url}"),
]


def synthetic_domain(rng: random.Random, index: int) -> str:
    token = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    suffix = ["top", "xyz", "click", "support", "site"][index]
    return f"netra-{token}-secure.{suffix}"


def message_bytes(case: dict) -> bytes:
    message = EmailMessage()
    message["Subject"] = case["subject"]
    message["From"] = case["sender"]
    message["To"] = "judge@example.org"
    message["Message-ID"] = f"<{case['id']}@benchmark.local>"
    message.set_content(case["body"])
    return message.as_bytes()


def build_cases(project: Path) -> list[dict]:
    rng = random.Random(SEED)
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    safe = []
    for index, (subject, template, url) in enumerate(SAFE_TOPICS, 1):
        values = {"day": rng.choice(days), "hour": rng.randint(9, 17), "number": rng.randint(10, 499),
                  "reference": f"REF-{rng.randint(10000, 99999)}"}
        body = template.format(**values) + (f" More information: {url}" if url else "")
        safe.append({"id": f"SAFE-{index:02d}", "label": "LEGITIMATE", "subject": subject,
                     "sender": f"updates{index}@example.org", "body": body, "url": url, "topic": subject})

    dataset_text = (project / "data" / "training_data.csv").read_text(encoding="utf-8", errors="ignore").lower()
    phishing = []
    for index, (subject, template) in enumerate(PHISHING_TEMPLATES):
        domain = synthetic_domain(rng, index)
        url = f"https://{domain}/account/login/verify?password=confirm&session={rng.randint(100000, 999999)}"
        assert domain.lower() not in dataset_text, f"Synthetic domain unexpectedly exists in the dataset: {domain}"
        phishing.append({"id": f"PHISH-{index + 1:02d}", "label": "PHISHING", "subject": subject,
                         "sender": f"security@{domain}", "body": template.format(url=url), "url": url,
                         "domain": domain, "topic": subject, "present_in_url_dataset": False})
    cases = safe + phishing
    rng.shuffle(cases)
    return cases


def evaluate(project: Path, output_root: Path) -> Path:
    sys.path.insert(0, str(project))
    from backend.services.analysis_orchestrator import AnalysisOrchestrator

    run_dir = output_root / time.strftime("run-%Y%m%d-%H%M%S")
    email_dir = run_dir / "generated_emails"
    email_dir.mkdir(parents=True)
    orchestrator = AnalysisOrchestrator()
    orchestrator.domain_provider.inspect = lambda domain, source="unknown", related_ips=None: {
        "domain": domain, "source": source, "findings": [], "records": {},
        "limitations": ["Live DNS disabled for deterministic benchmark timing."],
    }

    rows = []
    for case in build_cases(project):
        raw = message_bytes(case)
        (email_dir / f"{case['id']}.eml").write_bytes(raw)
        started = time.perf_counter()
        result = orchestrator.analyze(raw, "random_25_benchmark")
        latency_ms = (time.perf_counter() - started) * 1000
        predicted = "PHISHING" if result.risk_score >= PHISHING_THRESHOLD else "LEGITIMATE"
        url_items = result.parsed.get("url_analysis", {}).get("urls", [])
        url_ml = url_items[0].get("ml_analysis", {}) if url_items else {}
        email_ml = result.parsed.get("ml_analysis", {})
        rows.append({
            **case,
            "predicted": predicted,
            "correct": predicted == case["label"],
            "risk_score": result.risk_score,
            "classification": result.classification,
            "confidence": result.confidence,
            "latency_ms": round(latency_ms, 2),
            "email_ml_classification": email_ml.get("classification"),
            "email_ml_probability": email_ml.get("phishing_probability"),
            "email_ml_used_in_decision": email_ml.get("used_in_decision", False),
            "url_risk_score": url_items[0].get("risk_score") if url_items else None,
            "url_ml_classification": url_ml.get("classification") if url_items else None,
            "url_ml_probability": url_ml.get("phishing_probability") if url_items else None,
            "url_ml_used_in_score": url_ml.get("used_in_score", False) if url_items else False,
            "finding_rules": [finding.rule for finding in result.findings],
            "evidence_sha256": result.evidence.sha256,
        })

    tp = sum(row["label"] == "PHISHING" and row["predicted"] == "PHISHING" for row in rows)
    tn = sum(row["label"] == "LEGITIMATE" and row["predicted"] == "LEGITIMATE" for row in rows)
    fp = sum(row["label"] == "LEGITIMATE" and row["predicted"] == "PHISHING" for row in rows)
    fn = sum(row["label"] == "PHISHING" and row["predicted"] == "LEGITIMATE" for row in rows)
    latencies = [row["latency_ms"] for row in rows]
    warm_latencies = latencies[1:] or latencies
    metrics = {
        "seed": SEED, "classification_threshold": PHISHING_THRESHOLD, "samples": len(rows),
        "legitimate": 20, "phishing": 5, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": (tp + tn) / len(rows), "precision": tp / (tp + fp) if tp + fp else 0,
        "recall": tp / (tp + fn) if tp + fn else 0, "specificity": tn / (tn + fp) if tn + fp else 0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0,
        "cold_start_latency_ms": latencies[0],
        "average_latency_ms": statistics.mean(latencies), "median_latency_ms": statistics.median(latencies),
        "warm_average_latency_ms": statistics.mean(warm_latencies),
        "warm_p95_latency_ms": sorted(warm_latencies)[int(0.95 * (len(warm_latencies) - 1))],
        "p95_latency_ms": sorted(latencies)[int(0.95 * (len(latencies) - 1))], "max_latency_ms": max(latencies),
        "email_ml_connected_cases": sum(bool(row["email_ml_used_in_decision"]) for row in rows),
        "url_ml_connected_cases": sum(bool(row["url_ml_used_in_score"]) for row in rows),
        "novel_phishing_domains_absent_from_dataset": sum(row.get("present_in_url_dataset") is False for row in rows),
        "scope": "Seeded synthetic functional benchmark. These 25 results demonstrate behavior and latency, not population accuracy.",
    }

    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (run_dir / "results.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    with (run_dir / "results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        columns = [key for key in rows[0] if key not in {"finding_rules"}]
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)

    pct = lambda value: f"{value * 100:.2f}%"
    lines = ["# NETRA-Mail Random 25-Email Benchmark", "", f"- Seed: `{SEED}`",
             f"- Accuracy: **{pct(metrics['accuracy'])}**", f"- Precision: **{pct(metrics['precision'])}**",
             f"- Recall: **{pct(metrics['recall'])}**", f"- F1: **{pct(metrics['f1'])}**",
             f"- False-positive rate: **{pct(metrics['false_positive_rate'])}**",
             f"- Cold-start latency: **{metrics['cold_start_latency_ms']:.2f} ms**",
             f"- Warm average latency: **{metrics['warm_average_latency_ms']:.2f} ms**",
             f"- Warm P95 latency: **{metrics['warm_p95_latency_ms']:.2f} ms**",
             f"- New phishing domains absent from dataset: **{metrics['novel_phishing_domains_absent_from_dataset']}/5**",
             f"- Email ML used as corroborated evidence: **{metrics['email_ml_connected_cases']} cases**",
             f"- URL ML used as corroborated evidence: **{metrics['url_ml_connected_cases']} cases**", "",
             "> This is a reproducible synthetic functional benchmark. Dataset-level claims must use the separate domain-grouped URL holdout.", "",
             "| ID | Topic | Expected | Predicted | Risk | Latency | Email ML used | URL ML used |", "|---|---|---|---|---:|---:|---:|---:|"]
    for row in rows:
        lines.append(f"| {row['id']} | {row['topic']} | {row['label']} | {row['predicted']} | {row['risk_score']} | {row['latency_ms']:.2f} ms | {row['email_ml_used_in_decision']} | {row['url_ml_used_in_score']} |")
    (run_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    table = "".join(f"<tr class='{'ok' if row['correct'] else 'bad'}'><td>{html.escape(row['id'])}</td><td>{html.escape(row['topic'])}</td><td>{row['label']}</td><td>{row['predicted']}</td><td>{row['risk_score']}</td><td>{row['latency_ms']:.2f} ms</td><td>{row['email_ml_used_in_decision']}</td><td>{row['url_ml_used_in_score']}</td></tr>" for row in rows)
    document = f"""<!doctype html><meta charset='utf-8'><title>NETRA Random 25</title><style>body{{font:16px Segoe UI;background:#071426;color:#eaf4ff;margin:0}}header,main{{padding:26px 6%}}header{{background:linear-gradient(120deg,#092847,#08738a)}}h1{{color:#61dcff}}.cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}}.card{{background:#10243c;padding:16px;border-radius:12px}}.v{{font-size:28px;font-weight:800;color:#68e5a5}}table{{width:100%;border-collapse:collapse;margin-top:24px;background:#0e2036}}td,th{{padding:9px;border-bottom:1px solid #28445f;text-align:left}}th{{color:#61dcff}}.bad{{color:#ff998f}}@media(max-width:900px){{.cards{{grid-template-columns:1fr 1fr}}}}</style><header><h1>NETRA-Mail · Random 25-Email Benchmark</h1><p>20 legitimate topics · 5 novel phishing domains absent from training data</p></header><main><div class='cards'><div class='card'>Accuracy<div class='v'>{pct(metrics['accuracy'])}</div></div><div class='card'>Recall<div class='v'>{pct(metrics['recall'])}</div></div><div class='card'>False positives<div class='v'>{pct(metrics['false_positive_rate'])}</div></div><div class='card'>Warm average<div class='v'>{metrics['warm_average_latency_ms']:.2f} ms</div></div><div class='card'>Warm P95<div class='v'>{metrics['warm_p95_latency_ms']:.2f} ms</div></div><div class='card'>Cold start<div class='v'>{metrics['cold_start_latency_ms']:.2f} ms</div></div></div><table><thead><tr><th>ID</th><th>Topic</th><th>Expected</th><th>Predicted</th><th>Risk</th><th>Latency</th><th>Email ML</th><th>URL ML</th></tr></thead><tbody>{table}</tbody></table></main>"""
    (run_dir / "REPORT.html").write_text(document, encoding="utf-8")
    return run_dir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output-root", default=str(Path.home() / "Documents" / "NETRA-Mail-Random-25"))
    args = parser.parse_args()
    run_dir = evaluate(Path(args.project_root).resolve(), Path(args.output_root).resolve())
    metrics = json.loads((run_dir / "metrics.json").read_text())
    print(f"Results: {run_dir}")
    print(f"Accuracy: {metrics['accuracy'] * 100:.2f}%")
    print(f"False-positive rate: {metrics['false_positive_rate'] * 100:.2f}%")
    print(f"Recall: {metrics['recall'] * 100:.2f}%")
    print(f"Warm average / P95 latency: {metrics['warm_average_latency_ms']:.2f} / {metrics['warm_p95_latency_ms']:.2f} ms")
    print(f"Cold-start latency: {metrics['cold_start_latency_ms']:.2f} ms")
    if metrics["fp"] or metrics["fn"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
