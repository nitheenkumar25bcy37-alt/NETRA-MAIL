"""Bounded inference adapter for the evaluated URL character model."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
from threading import RLock
from typing import Any, Dict

import joblib


class URLMLClassifier:
    MODEL_PATH = Path(os.getenv(
        "NETRA_URL_MODEL_PATH",
        str(Path(__file__).resolve().parent.parent / "data" / "url_domain_holdout_model.joblib"),
    ))
    _cached_model = None
    _cache_key = None
    _lock = RLock()

    @classmethod
    def _load(cls):
        if not cls.MODEL_PATH.is_file():
            raise RuntimeError("Evaluated URL model is unavailable.")
        stat = cls.MODEL_PATH.stat()
        if stat.st_size > 64 * 1024 * 1024:
            raise RuntimeError("URL model artifact exceeds the size limit.")
        expected = os.getenv("NETRA_URL_MODEL_SHA256", "").strip().lower()
        key = (str(cls.MODEL_PATH.resolve()), stat.st_mtime_ns, stat.st_size, expected)
        with cls._lock:
            if key == cls._cache_key and cls._cached_model is not None:
                return cls._cached_model
            artifact_bytes = cls.MODEL_PATH.read_bytes()
            if expected and hashlib.sha256(artifact_bytes).hexdigest() != expected:
                raise RuntimeError("URL model integrity verification failed.")
            artifact = joblib.load(io.BytesIO(artifact_bytes))
            if not isinstance(artifact, dict) or not {"model", "vectorizer"}.issubset(artifact):
                raise RuntimeError("URL model artifact has an unexpected structure.")
            if set(artifact["model"].classes_) != {0, 1}:
                raise RuntimeError("URL model artifact has unexpected classes.")
            cls._cached_model, cls._cache_key = artifact, key
            return artifact

    @classmethod
    def predict(cls, url: str) -> Dict[str, Any]:
        value = str(url or "")[:4096]
        artifact = cls._load()
        features = artifact["vectorizer"].transform([value])
        model = artifact["model"]
        predicted = int(model.predict(features)[0])
        probabilities = model.predict_proba(features)[0]
        classes = [int(item) for item in model.classes_]
        probability = float(dict(zip(classes, probabilities)).get(1, 0.0))
        return {
            "available": True,
            "classification": "PHISHING" if predicted == 1 else "LEGITIMATE",
            "phishing_probability": round(probability, 4),
            "model": "character TF-IDF + Logistic Regression",
            "evaluation": "domain-grouped unseen-domain holdout",
            "limitations": [
                "The ML result is supporting evidence and cannot block a URL without corroborating structural evidence."
            ],
        }

