"""Aggregate the frozen runs without choosing only the best-performing split."""
import hashlib
import json
from pathlib import Path


def main():
    root = Path("evaluation_results/upgrades")
    manifest = json.loads(Path("backend/data/content_model/linear.json.manifest.json").read_text())
    reports = ["reliability", "reliability_audit", "reliability_final_audit"]
    output = {"scope": "600 offline public emails; first two sets informed development, final 200 reserved until model freeze",
              "model_sha256": manifest["sha256"], "threshold": 35,
              "positive_definition": "Flagged for review at risk score >=35, including inconclusive cases; not confirmed malicious verdicts",
              "splits": {}, "limitations": [
                  "Same source/time distributions: Nazario 2025 phishing versus SpamAssassin 2002 easy ham.",
                  "Hash-disjoint from public training; approximate template filtering cannot rule out all related messages.",
                  "Network intelligence and live authentication excluded; attachment inspection depends on local worker availability.",
                  "Not an independent-source, production or multilingual accuracy estimate."]}
    for stage in ("before", "after"):
        counts = {k: 0 for k in ("tp", "tn", "fp", "fn", "errors", "total")}
        seen = set(manifest["training_hashes"])
        for name in reports:
            path = root / f"{name}_{stage}.json"
            report = json.loads(path.read_text())
            hashes = {row["sha256"] for row in report["rows"]}
            assert len(hashes) == report["total"] == 200 and not seen & hashes
            assert report["threshold"] == 35 and report["errors"] == 0
            if stage == "after":
                assert report["pipeline_version"] == "4.7.0"
            seen.update(hashes)
            for key in counts:
                counts[key] += report[key]
            output["splits"][f"{name}_{stage}"] = {"report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                **{k: report[k] for k in counts}}
        tp, tn, fp, fn = (counts[k] for k in ("tp", "tn", "fp", "fn"))
        output[stage] = {**counts, "accuracy": (tp + tn) / counts["total"],
            "precision": tp / (tp + fp), "recall": tp / (tp + fn),
            "f1": 2 * tp / (2 * tp + fp + fn), "false_positive_rate": fp / (fp + tn)}
    (root / "reliability_summary.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({stage: output[stage] for stage in ("before", "after")}, indent=2))


if __name__ == "__main__":
    main()
