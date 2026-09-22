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
    if task.get("operation") != "attachment":
        raise ValueError("unsupported_operation")
    data = base64.b64decode(task["data"], validate=True)
    if len(data) > 10 * 1024 * 1024:
        raise ValueError("attachment_limit")
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
