"""Validate evaluation inputs before reporting any accuracy."""
import hashlib
from pathlib import Path


def validate_cases(cases, base: Path):
    if not isinstance(cases, list) or not cases:
        raise ValueError("Evaluation requires a nonempty JSON array")
    base = base.resolve()
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("malicious"), bool) or not isinstance(case.get("path"), str):
            raise ValueError("Each case requires a path and boolean malicious label")
        path = (base / case["path"]).resolve()
        if not path.is_relative_to(base) or not path.is_file():
            raise ValueError("Evaluation files must exist inside the manifest directory")
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("Evaluation message exceeds 10 MB")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen:
            raise ValueError("Duplicate email content would bias evaluation metrics")
        seen.add(digest)
        if case.get("sha256") and case["sha256"] != digest:
            raise ValueError("Evaluation message hash does not match manifest")
    return cases
