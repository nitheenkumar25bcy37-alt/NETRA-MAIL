import csv
import os
import hashlib
import io
import json
import math
from threading import RLock
from pathlib import Path
from typing import Dict, List

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from backend.config import MODEL_PATH as CONFIGURED_MODEL_PATH


class LocalMLClassifier:
    BASE_DIR = Path(__file__).resolve().parent
    MODEL_PATH = Path(CONFIGURED_MODEL_PATH)
    DATASET_PATH = Path(os.getenv("NETRA_EMAIL_DATASET_PATH", str(BASE_DIR / "data" / "training_data.csv")))
    _cache_key = None
    _cached_model = None
    _lock = RLock()

    BOOTSTRAP = [
        ("Meeting moved to 3 PM tomorrow. See you then.", "LEGITIMATE"),
        ("Please find the quarterly report attached for review.", "LEGITIMATE"),
        ("Lunch meeting confirmed for Friday at noon.", "LEGITIMATE"),
        ("Your account has been suspended. Verify your identity immediately.", "PHISHING"),
        ("Urgent payment required. Click the secure link to confirm your bank account.", "PHISHING"),
        ("Your password expires today. Login now to prevent account termination.", "PHISHING"),
        ("Please process this wire transfer immediately to the new beneficiary.", "PHISHING"),
        ("Final notice: confirm your payment information within 24 hours.", "PHISHING"),
        ("Your Microsoft account requires security verification. Click here to sign in.", "PHISHING"),
        ("Please review the attached project minutes and action items.", "LEGITIMATE"),
        ("The team standup is scheduled for 10 AM tomorrow.", "LEGITIMATE"),
        ("Thanks for sending the invoice. We will review it this week.", "LEGITIMATE"),
    ]

    @classmethod
    def _dataset(cls):
        if cls.DATASET_PATH.exists():
            rows = []
            with cls.DATASET_PATH.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                if not {"text", "label"}.issubset(reader.fieldnames or []):
                    raise ValueError("Email training data requires text,label columns; URL datasets are not compatible.")
                for row in reader:
                    text = (row.get("text") or "").strip()
                    label = (row.get("label") or "").strip().upper()
                    if text and label in {"PHISHING", "LEGITIMATE"}:
                        rows.append((text, label))
            if len(rows) >= 10 and len({x[1] for x in rows}) == 2:
                return rows
        return cls.BOOTSTRAP

    @classmethod
    def train(cls):
        cls.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = cls._dataset()
        X = [x[0] for x in data]
        y = [x[1] for x in data]

        model = Pipeline([
            ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True)),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ])
        model.fit(X, y)
        joblib.dump(model, cls.MODEL_PATH)
        return model

    @classmethod
    def _load(cls):
        if not cls.MODEL_PATH.exists():
            raise RuntimeError("Email model is unavailable; train and provision an evaluated model explicitly.")
        expected = os.getenv("NETRA_MODEL_SHA256", "").lower().strip()
        with cls._lock:
            stat = cls.MODEL_PATH.stat()
            key = (str(cls.MODEL_PATH.resolve()), stat.st_mtime_ns, stat.st_size, expected)
            if key == cls._cache_key and cls._cached_model is not None:
                return cls._cached_model
            if stat.st_size > 64 * 1024 * 1024:
                raise RuntimeError("Email model artifact exceeds the size limit.")
            artifact = cls.MODEL_PATH.read_bytes()
            if expected and hashlib.sha256(artifact).hexdigest() != expected:
                raise RuntimeError("Email model integrity verification failed.")
            try:
                # Deserialize exactly the bytes that were hashed.
                model = joblib.load(io.BytesIO(artifact))
                if set(model.classes_) != {"PHISHING", "LEGITIMATE"}:
                    raise ValueError("Unexpected email model labels")
            except Exception as exc:
                raise RuntimeError("Email model could not be loaded; explicit retraining is required.") from exc
            cls._cache_key, cls._cached_model = key, model
            return model

    @classmethod
    def predict(cls, email_text: str) -> Dict:
        model = cls._load()
        text = email_text or ""
        prediction = str(model.predict([text])[0]).upper()
        probabilities = model.predict_proba([text])[0]
        classes = list(model.classes_)
        probability_map = dict(zip(classes, probabilities))
        phishing_probability = float(probability_map.get("PHISHING", 0.0))

        raw_probability = phishing_probability
        calibration_status = "not_configured"
        calibration_path = Path(os.getenv("NETRA_ML_CALIBRATION", str(cls.MODEL_PATH.parent / "email_probability_calibration.json")))
        if calibration_path.exists():
            try:
                params = json.loads(calibration_path.read_text(encoding="utf-8"))
                if params["model_sha256"] != hashlib.sha256(cls.MODEL_PATH.read_bytes()).hexdigest():
                    raise ValueError("Calibration belongs to a different model")
                slope, intercept = float(params["slope"]), float(params["intercept"])
                if not params.get("activated", False) or not math.isfinite(slope) or not math.isfinite(intercept) or not 0 < slope <= 100 or abs(intercept) > 100:
                    raise ValueError("Invalid calibration parameters")
                logit = math.log(max(1e-6, raw_probability) / max(1e-6, 1-raw_probability))
                value = max(-30, min(30, float(params["slope"])*logit + float(params["intercept"])))
                phishing_probability = 1/(1+math.exp(-value))
                calibration_status = "platt_scaling"
                prediction = "PHISHING" if phishing_probability >= .5 else "LEGITIMATE"
            except (OSError, ValueError, KeyError, TypeError):
                calibration_status = "invalid_or_stale"
        return {
            "raw_phishing_probability": round(raw_probability, 4),
            "calibration_status": calibration_status,
            "classification": prediction,
            "phishing_probability": round(phishing_probability, 4),
            "confidence": round(max(phishing_probability, 1-phishing_probability) * 100, 2),
            "model": "TF-IDF + Logistic Regression",
            "training_source": "unverified model artifact provenance",
            "limitations": ["Model probabilities are not calibrated safety guarantees.", "Independent end-to-end evaluation is required."],
        }
