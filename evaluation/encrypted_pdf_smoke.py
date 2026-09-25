"""Real local-worker smoke checks using synthetic encrypted PDFs, not a benchmark.

Run: python -m evaluation.encrypted_pdf_smoke
No document passwords or plaintext are written to the result artifact.
"""
import hashlib
import io
import json
import os
import time
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader


def document(kind):
    source = io.BytesIO()
    pdf = canvas.Canvas(source)
    if kind == "qr":
        import cv2
        from PIL import Image
        matrix = cv2.QRCodeEncoder_create().encode("https://paypal.verify-account.xyz.com/login")
        image = Image.fromarray(matrix).resize((450, 450), Image.Resampling.NEAREST)
        pdf.drawImage(ImageReader(image), 50, 250, width=300, height=300)
    else:
        text = "Your monthly statement. No action is required."
        if kind == "phishing":
            text = "Send your password immediately to https://paypal.verify-account.xyz.com/login"
        pdf.drawString(30, 740, text)
    pdf.showPage()
    pdf.save()
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(source.getvalue())))
    if kind == "active":
        writer.add_js("app.alert('synthetic static inspection test')")
    writer.encrypt("synthetic-demo-password", algorithm="AES-256")
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def run():
    from backend.attachment_review import review_pdf
    os.environ["NETRA_INSPECTION_MODE"] = "portable"
    rows = []
    for kind in ("benign", "phishing", "qr", "active", "wrong_password"):
        data = document(kind)
        start = time.perf_counter()
        review = review_pdf(data, "incorrect" if kind == "wrong_password" else "synthetic-demo-password",
                            "synthetic-smoke", hashlib.sha256(data).hexdigest(), "local-evaluation")
        expected = "not_inspected" if kind == "wrong_password" else "suspicious" if kind in {"phishing", "qr", "active"} else "no_threats_detected"
        rows.append({"case": kind, "expected": expected, "status": review["status"],
                     "passed": review["status"] == expected, "latency_seconds": round(time.perf_counter() - start, 3),
                     "pages": [{"page": p["page"], "checks": p["checks"], "qr_count": p["qr_count"]} for p in review["pages"]]})
        print(kind, review["status"], rows[-1]["latency_seconds"], flush=True)
    output = {"scope": "Five synthetic functional smoke cases, local Windows portable worker. Not detection accuracy or a production latency benchmark.",
              "passed": sum(r["passed"] for r in rows), "total": len(rows), "results": rows}
    target = Path("evaluation_results/upgrades/encrypted_pdf_smoke.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return output


if __name__ == "__main__":
    outcome = run()
    raise SystemExit(0 if outcome["passed"] == outcome["total"] else 1)
