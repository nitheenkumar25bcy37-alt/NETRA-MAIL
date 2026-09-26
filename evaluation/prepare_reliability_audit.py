"""Freeze unused public messages before scoring. Exclude overlapping templates."""
import hashlib
import argparse
import io
import json
import mailbox
import random
import tarfile
from pathlib import Path
from evaluation.prepare_public_emails import download, SOURCES
from evaluation.train_content_model import extract, group
from backend.content_model import normalize


def shingles(text):
    words = normalize(text).split()[:2000]
    return set(tuple(words[i:i+5]) for i in range(max(1, len(words)-4)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--final", action="store_true", help="Exclude the previous audit as well, and freeze a final untouched set")
    args = parser.parse_args()
    root = Path(".local-corpora")
    audit_name = "reliability-final-audit" if args.final else "reliability-audit"
    destination = root / audit_name
    destination.mkdir(exist_ok=True)
    if (destination / "test.json").exists():
        raise ValueError("Audit already frozen; do not resample after looking at scores")
    used = sum([json.loads((root / (name + ".json")).read_text()) for name in ("calibration", "test")], [])
    if args.final:
        prior_rows = json.loads((root / "reliability-audit" / "test.json").read_text())
        used.extend([{**row, "path": str(Path("reliability-audit") / row["path"])} for row in prior_rows])
    hashes = {row["sha256"] for row in used}
    texts = [extract((root / row["path"]).read_bytes()) for row in used]
    groups = {group(t) for t in texts}
    prior = [shingles(t) for t in texts]
    provenance = json.loads((root / "provenance.json").read_text())
    box = mailbox.mbox(root / "nazario.mbox")
    phishing = [message.as_bytes() for message in box]
    box.close()
    archive_bytes = download(SOURCES["ham"])
    assert hashlib.sha256(archive_bytes).hexdigest() == provenance["ham"]["sha256"]
    legitimate = []
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:bz2") as archive:
        for member in archive:
            if member.isfile() and member.size < 2 * 1024 * 1024 and not member.name.endswith("cmds"):
                legitimate.append(archive.extractfile(member).read())
    selected = []
    rejected = {"hash": 0, "template": 0}
    for label, candidates in [(True, phishing), (False, legitimate)]:
        random.Random(9262026).shuffle(candidates)
        count = 0
        for raw in candidates:
            digest = hashlib.sha256(raw).hexdigest()
            if digest in hashes:
                rejected["hash"] += 1
                continue
            text = extract(raw)
            signature, tokens = group(text), shingles(text)
            if signature in groups or any(len(tokens & p) / max(1, len(tokens | p)) >= .8 for p in prior):
                rejected["template"] += 1
                continue
            name = digest + ".eml"
            (destination / name).write_bytes(raw)
            selected.append({"path": name, "sha256": digest, "malicious": label,
                             "source": "nazario_2025" if label else "spamassassin_easy_ham"})
            hashes.add(digest); groups.add(signature); prior.append(tokens)
            count += 1
            if count == 100:
                break
        if count != 100:
            raise ValueError(f"Only {count} non-overlapping messages for class {label}; do not relax exclusions to reach a desired score")
    encoded = json.dumps(selected, indent=2)
    (destination / "test.json").write_text(encoded)
    report = {"messages": len(selected), "source_provenance": provenance,
              "manifest_sha256": hashlib.sha256(encoded.encode()).hexdigest(), "rejected": rejected,
              "exclusions": "All original development and test hashes, first-80-token groups, and >=0.8 Jaccard five-word-shingle similarity; also applied within the audit.",
              "limitations": ["Same source/time distributions; not an independent-source or modern bank-email benchmark.",
                              "Template exclusion is approximate, not a guarantee of semantic independence."]}
    report["excluded_previous_messages"] = len(used)
    Path("evaluation_results/upgrades/" + audit_name.replace("-", "_") + "_provenance.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
