"""Restricted subprocess entry point for hosted static attachment inspection."""
from __future__ import annotations

import base64
import contextlib
import json
from pathlib import Path
import signal
import sys

# ``python -I`` deliberately excludes the working directory. Add only this
# trusted repository root so the worker cannot import from user-site paths.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> None:
    if hasattr(signal, "alarm"):
        signal.alarm(30)
    raw = sys.stdin.buffer.read(15 * 1024 * 1024 + 1)
    if len(raw) > 15 * 1024 * 1024:
        raise ValueError("input_limit")
    task = json.loads(raw)
    if task.get("operation") not in {"attachment", "pdf_unlock"}:
        raise ValueError("unsupported_operation")
    data = base64.b64decode(task["data"], validate=True)
    if len(data) > 10 * 1024 * 1024:
        raise ValueError("attachment_limit")
    if task.get("operation") == "pdf_unlock":
        # Defense in depth for portable Python libraries. OS network isolation
        # is provided by Docker mode; this hook is not a native-code sandbox.
        def deny_network(event, args):
            if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
                raise PermissionError("PDF inspection is offline")
        sys.addaudithook(deny_network)
        with contextlib.redirect_stdout(sys.stderr):
            from backend.pdf_inspection import inspect_pdf
            password = task.pop("password", "")
            baseline = inspect_pdf(data, password, visual_checks=False)
        # Preserve completed decryption/text/active-content checks before
        # optional OCR native libraries can exhaust the worker's budget.
        sys.stdout.write(json.dumps(baseline, ensure_ascii=True) + "\n")
        sys.stdout.flush()
        if not baseline.get("available"):
            return
        with contextlib.redirect_stdout(sys.stderr):
            result = inspect_pdf(data, password)
        sys.stdout.write(json.dumps(result, ensure_ascii=True))
        return
    content_type = str(task.get("content_type", ""))[:200]
    filename = str(task.get("filename", ""))[:1024]
    with contextlib.redirect_stdout(sys.stderr):
        image = {}
        if content_type.lower().startswith("image/"):
            from backend.image_analyzer import analyze_image
            image = analyze_image(data, content_type)
        from backend.attachment_analyzer import AttachmentAnalyzer
        static = AttachmentAnalyzer._analyze_one({
            "filename": filename,
            "content_type": content_type,
            "content": data,
            "size_bytes": len(data),
            "image_analysis": image,
        })
        urls = list(static.get("embedded_urls", []))
        if content_type in {"text/html", "text/plain", "application/javascript"}:
            import re
            urls.extend(re.findall(r"https?://[^\s<>\"']+", data[:524288].decode("utf-8", errors="ignore"))[:100])
        urls.extend(value for value in image.get("qr_payloads", []) if value.lower().startswith(("https://", "http://")))
    result = {
        "available": True,
        "inspection_mode": "portable_subprocess",
        "static_analysis": static,
        "image_analysis": image,
        "embedded_urls": list(dict.fromkeys(value[:2048] for value in urls))[:100],
        "archive_members": static.get("archive_members", []),
    }
    encoded = json.dumps(result, ensure_ascii=True).encode()
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("output_limit")
    sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stdout.write('{"available":false,"error":"portable_inspection_failed"}')
