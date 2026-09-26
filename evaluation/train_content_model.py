"""Fit on development messages only; grouped CV selects threshold, never test labels."""
import gzip
import hashlib
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from backend.content_model import ROOT, content_text, features, normalize
from backend.parser import ForensicEmailParser


def extract(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parser = ForensicEmailParser()
    plain, html = parser._extract_bodies(msg)
    visible = parser._extract_html_details(html)["visible_text"]
    return content_text({"metadata": {"subject": str(msg.get("Subject", ""))},
                         "body": {"plain": plain, "visible_text": visible}})


def group(text):
    return hashlib.sha256(" ".join(normalize(text).split()[:80]).encode()).hexdigest()


def main():
    root = Path(".local-corpora")
    rows = json.loads((root / "calibration.json").read_text())
    test_hashes = {r["sha256"] for r in json.loads((root / "test.json").read_text())}
    assert not test_hashes & {r["sha256"] for r in rows}, "Training/test hash overlap"
    texts = []
    for row in rows:
        raw = (root / row["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("Training message hash differs from frozen manifest")
        texts.append(extract(raw))
    y = np.array([int(r["malicious"]) for r in rows])
    groups = np.array([group(t) for t in texts])
    x = features(texts)
    context_rows = json.loads(Path("evaluation/content_context_examples.json").read_text())
    context_texts = [r["text"] for r in context_rows]
    context_y = np.array([int(r["malicious"]) for r in context_rows])
    context_x = features(context_texts)
    from scipy.sparse import vstack
    oof = np.zeros(len(y))
    splits = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=26106)
    for train, val in splits.split(x, y, groups):
        model = LogisticRegression(C=4, max_iter=1000, class_weight="balanced", random_state=26106)
        model.fit(vstack([x[train], context_x]), np.concatenate([y[train], context_y]))
        oof[val] = model.predict_proba(x[val])[:, 1]
    candidates = []
    for threshold in np.arange(.5, .901, .025):
        predicted = oof >= threshold
        tp = int(sum(predicted & (y == 1))); fp = int(sum(predicted & (y == 0)))
        tn = int(sum(~predicted & (y == 0))); fn = int(sum(~predicted & (y == 1)))
        candidates.append({"threshold": round(float(threshold), 3), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                           "f1": 2 * tp / max(1, 2 * tp + fp + fn), "fpr": fp / sum(y == 0)})
    eligible = [r for r in candidates if r["fpr"] <= .03]
    if not eligible:
        raise ValueError("No development threshold meets the false-positive budget")
    selected = max(eligible, key=lambda r: (r["f1"], -r["fp"], r["threshold"]))
    model = LogisticRegression(C=4, max_iter=1000, class_weight="balanced", random_state=26106).fit(vstack([x, context_x]), np.concatenate([y, context_y]))
    payload = {"schema": 1, "threshold": selected["threshold"], "intercept": float(model.intercept_[0]),
               "weights": [round(float(v), 10) for v in model.coef_[0]]}
    ROOT.mkdir(parents=True, exist_ok=True)
    encoded = gzip.compress(json.dumps(payload, separators=(",", ":")).encode(), mtime=0)
    path = ROOT / "linear.json.gz"
    path.write_bytes(encoded)
    manifest = {"sha256": hashlib.sha256(encoded).hexdigest(), "training_samples": len(rows) + len(context_rows),
                "public_training_samples": len(rows), "synthetic_context_samples": len(context_rows),
                "synthetic_context_sha256": hashlib.sha256(Path("evaluation/content_context_examples.json").read_bytes()).hexdigest(),
                "training_hashes": sorted(r["sha256"] for r in rows), "training_groups": sorted(set(groups)),
                "development_selection": selected, "provenance": json.loads((root / "provenance.json").read_text()),
                "limitations": ["200 development messages from two different source/time distributions.",
                                "First-80-token grouping reduces exact template leakage but cannot eliminate near duplicates.",
                                "No held-out test labels used to fit weights or select threshold."]}
    path.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2))
    report = {"training_samples": len(rows), "template_groups": len(set(groups)),
              "selection": selected, "candidate_thresholds": candidates,
              "synthetic_context_samples": len(context_rows),
              "scope": "Grouped out-of-fold public development results, with fixed synthetic contrasts in each training fold; not held-out performance."}
    Path("evaluation_results/upgrades/content_model_development.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
