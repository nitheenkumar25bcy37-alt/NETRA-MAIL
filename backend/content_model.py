"""Non-executable, bounded word/character text model for inconclusive emails."""
import gzip
import hashlib
import io
import json
import os
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import HashingVectorizer

ROOT = Path(__file__).parent / "data" / "content_model"
FEATURES = 32768


def content_text(parsed):
    body = parsed.get("body") or {}
    # Sender addresses, Received headers, timestamps and corpus provenance are
    # deliberately excluded. Identity verification is handled independently.
    return "\n".join([str((parsed.get("metadata") or {}).get("subject", "")),
        str(body.get("plain", "")), str(body.get("visible_text", "")),
        *[str(item.get("image_analysis", {}).get("ocr_text", "")) for item in parsed.get("attachments", [])]])[:100000]


def normalize(text):
    text = unicodedata.normalize("NFKC", str(text)[:100000]).lower()
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    addresses = re.findall(r"[\w.+-]+@[\w.-]+", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+", " address ", text)
    for address in addresses:
        local = address.split("@", 1)[0]
        if len(local) >= 3:
            text = re.sub(r"\b" + re.escape(local) + r"\b", " recipient ", text)
    text = re.sub(r"https?://\S+|www\.\S+", " link ", text)
    text = re.sub(r"\b[\w-]+(?:\.[\w-]+)+\b", " domain ", text)
    text = re.sub(r"\b\w*[0-9]\w*\b", " number ", text)
    return re.sub(r"\s+", " ", text).strip()


def features(texts):
    cleaned = [normalize(t) for t in texts]
    word = HashingVectorizer(n_features=FEATURES, alternate_sign=False,
                            ngram_range=(1, 2), norm="l2")
    char = HashingVectorizer(n_features=FEATURES, alternate_sign=False,
                            analyzer="char_wb", ngram_range=(3, 5), norm="l2")
    return hstack([word.transform(cleaned), char.transform(cleaned)], format="csr")


@lru_cache(maxsize=2)
def _load(path, stamp, size, manifest_stamp):
    artifact = Path(path)
    manifest = json.loads(artifact.with_suffix(".manifest.json").read_text())
    if size > 4 * 1024 * 1024:
        raise ValueError("Model too large")
    raw = artifact.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
        raise ValueError("Model integrity mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        decoded = stream.read(4 * 1024 * 1024 + 1)
    if len(decoded) > 4 * 1024 * 1024:
        raise ValueError("Model expanded size limit")
    model = json.loads(decoded)
    weights = np.asarray(model["weights"], dtype=float)
    threshold = float(model["threshold"])
    intercept = float(model["intercept"])
    if (model["schema"] != 1 or weights.shape != (FEATURES * 2,)
            or not np.isfinite(weights).all() or not np.isfinite(intercept)
            or not .5 <= threshold <= .99):
        raise ValueError("Invalid content model")
    return weights, intercept, threshold, manifest


def predict(text):
    if os.getenv("NETRA_CONTENT_MODEL_ENABLED", "true").lower() in {"false", "0", "no"}:
        return {"available": False, "reason": "disabled"}
    path = Path(os.getenv("NETRA_CONTENT_MODEL_PATH", str(ROOT / "linear.json.gz")))
    try:
        stat = path.stat()
        weights, intercept, threshold, manifest = _load(str(path), stat.st_mtime_ns, stat.st_size,
                                                       path.with_suffix(".manifest.json").stat().st_mtime_ns)
        margin = float((features([text]) @ weights)[0]) + intercept
        score = float(1 / (1 + np.exp(-np.clip(margin, -35, 35))))
        return {"available": True, "model": "Hashed word + character logistic regression",
                "decision_score": round(score, 6), "threshold": threshold,
                "request_review": score >= threshold, "training_samples": manifest["training_samples"],
                "public_training_samples": manifest.get("public_training_samples", manifest["training_samples"]),
                "synthetic_context_samples": manifest.get("synthetic_context_samples", 0),
                "model_sha256": manifest["sha256"], "used_in_decision": False,
                "limitations": ["Decision score is not a calibrated probability of harm.",
                                 "Public-corpus source/time shift and template similarity limit generalization."]}
    except (OSError, EOFError, ValueError, KeyError, TypeError, OverflowError):
        return {"available": False, "reason": "model_unavailable_or_invalid"}
