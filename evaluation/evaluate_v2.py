"""Offline v2 corpus evaluation. Run with python -m evaluation.evaluate_v2."""
import argparse
import hashlib
import json
import math
import os
import statistics
import time
from pathlib import Path

from backend.services.analysis_orchestrator import AnalysisOrchestrator
from evaluation.deterministic.run_evaluation import EXPECTED
from evaluation.manifest_validation import validate_cases


class OfflineDomains:
    def inspect(self, *args, **kwargs):
        return {"findings": [], "lookup_available": False, "limitations": ["Offline evaluation: DNS disabled."]}


class OfflineIPs:
    def lookup(self, ip):
        return {"ip": ip, "available": False, "source": "offline"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, help='JSON array of {"path": "message.eml", "malicious": true}. Paths relative to manifest.')
    parser.add_argument("--threshold", type=int, default=25)
    parser.add_argument("--html", type=Path, help="Optional readable HTML report")
    args = parser.parse_args()
    if not 0 <= args.threshold <= 100:
        parser.error("Threshold must be between 0 and 100")
    if args.manifest:
        cases = json.loads(args.manifest.read_text(encoding="utf-8"))
        base = args.manifest.parent
    else:
        cases = [{"path": name, "malicious": info["threat"]} for name, info in EXPECTED.items()]
        base = Path(__file__).parent / "deterministic" / "emails"
    try:
        validate_cases(cases, base)
    except ValueError as exc:
        parser.error(str(exc))
    analyzer = AnalysisOrchestrator(ip_provider=OfflineIPs(), domain_provider=OfflineDomains())
    # Offline means even signed samples cannot issue DNS requests.
    from unittest.mock import patch
    rows, timings = [], []
    tp = tn = fp = fn = errors = 0
    with patch.dict(os.environ, {"NETRA_URL_REPUTATION_ENABLED": "false", "NETRA_EXPAND_SHORT_URLS": "0"}), \
         patch("backend.email_authentication.EmailAuthenticationVerifier._arc", return_value={"status": "unavailable", "source": "offline"}), \
         patch("backend.dkim_verifier.DKIMVerifier.verify", return_value={"status": "unavailable", "source": "offline", "limitations": ["DNS verification disabled for offline evaluation."]}):
        for case in cases:
            started = time.perf_counter()
            try:
                raw = (base / case["path"]).read_bytes()
                result = analyzer.analyze(raw)
                predicted = result.risk_score >= args.threshold
                expected = case["malicious"]
                tp += predicted and expected
                tn += not predicted and not expected
                fp += predicted and not expected
                fn += not predicted and expected
                rows.append({"path": case["path"], "sha256": hashlib.sha256(raw).hexdigest(), "expected": expected, "predicted": predicted, "risk_score": result.risk_score})
            except Exception as exc:
                errors += 1
                rows.append({"path": case["path"], "error": type(exc).__name__})
            timings.append(time.perf_counter() - started)
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    report = {
        "scope": "user-supplied labels; independence unverified" if args.manifest else "synthetic regression only; not real-world detection accuracy",
        "pipeline_version": analyzer.VERSION, "threshold": args.threshold,
        "network": "disabled", "total": len(cases), "errors": errors,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "successful_case_accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "end_to_end_correct_fraction": ratio(tp + tn, len(cases)),
        "latency_mean_seconds": statistics.mean(timings),
        "latency_p95_seconds": sorted(timings)[max(0, math.ceil(len(timings) * 0.95) - 1)],
        "rows": rows,
        "limitations": ["No production-accuracy claim. External intelligence and local DKIM verification are excluded.", "Supplied dataset independence and provenance must be checked separately.", "Errors are reported separately, not silently counted as safe."],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.html:
        from evaluation.html_report import render_report
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(render_report(report), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}, indent=2))


if __name__ == "__main__":
    main()
