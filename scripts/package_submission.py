"""Create a source-only implementation candidate with per-file checksums.

No runtime data, models, mail, credentials, caches or evaluation results are
selected. Acceptance status is intentionally not inferred from a successful ZIP.
"""
import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sources():
    for folder in ("backend", "dashboard", "evaluation", "scripts", "tests"):
        for path in (ROOT / folder).rglob("*.py"):
            relative = path.relative_to(ROOT)
            if path.is_symlink() or any(part in {"data", "__pycache__", ".venv"} for part in relative.parts):
                continue
            yield path
    for folder, suffixes in (("extension", {".js", ".html", ".css", ".png", ".svg"}), ("docs", {".md"}), ("inspection", {".txt", ".md"})):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and not path.is_symlink() and path.suffix in suffixes:
                yield path
    for name in ("extension/manifest.json", "inspection/Dockerfile", "inspection/Dockerfile.dockerignore",
            "requirements.txt", "requirements-dev.txt", "requirements-gmail.txt", "requirements-evaluation.txt",
            "requirements-submission.lock", "backend/requirements.txt", "backend/.env.example",
            "backend/README.md", "pytest.ini", ".gitignore", "tests/extension_security.test.cjs"):
        path = ROOT / name
        if path.is_file() and not path.is_symlink():
            yield path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target = args.output.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(set(sources()))
    records = []
    # Exclusive creation prevents silently replacing an earlier checkpoint.
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            data = path.read_bytes()
            name = path.relative_to(ROOT).as_posix()
            records.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
        manifest = {"version": "4.4.0", "status": "implementation_candidate_acceptance_deferred",
            "excluded": ["mail", "databases", "evidence", "tokens", "models", "evaluation results", "virtual environments"],
            "limitations": ["Source-only selection is not a secret scan or security review.", "Dependency lock describes the current Windows environment; other platforms require a separate lock.", "No independent accuracy claim or release acceptance is included."],
            "files": records}
        info = zipfile.ZipInfo("SUBMISSION_MANIFEST.json", date_time=(2026, 1, 1, 0, 0, 0))
        archive.writestr(info, json.dumps(manifest, indent=2))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(target.suffix + ".sha256").write_text(digest + "  " + target.name + "\n")
    print(json.dumps({"archive": str(target), "sha256": digest, "files": len(records), "status": manifest["status"]}))


if __name__ == "__main__":
    main()
