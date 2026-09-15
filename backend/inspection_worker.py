"""Private container entry point; JSON stdin/stdout, no host service imports."""
import base64
import contextlib
import json
import os
import signal
import sys


def main():
    # Independent wall-clock limit also applies if the supervising CLI dies.
    signal.alarm(30)
    raw = sys.stdin.buffer.read(15 * 1024 * 1024 + 1)
    if len(raw) > 15 * 1024 * 1024:
        raise ValueError("input_limit")
    task = json.loads(raw)
    with contextlib.redirect_stdout(sys.stderr):
        if task.get("operation") == "attachment":
            from backend.attachment_analyzer import AttachmentAnalyzer
            data = base64.b64decode(task["data"], validate=True)
            if len(data) > 10 * 1024 * 1024:
                raise ValueError("attachment_limit")
            content_type = str(task.get("content_type", ""))[:200]
            image = {}
            if content_type.startswith("image/"):
                from backend.image_analyzer import analyze_image
                image = analyze_image(data, content_type)
            item = {"filename": str(task.get("filename", ""))[:1024],
                "content_type": content_type, "content": data,
                "size_bytes": len(data), "image_analysis": image}
            static = AttachmentAnalyzer._analyze_one(item)
            urls = list(static.get("embedded_urls", []))
            if content_type in {"text/html", "text/plain", "application/javascript"}:
                import re
                urls.extend(re.findall(r"https?://[^\s<>\"']+", data[:524288].decode("utf-8", errors="ignore"))[:100])
            urls.extend(value for value in image.get("qr_payloads", []) if value.lower().startswith(("https://", "http://")))
            result = {"available": True, "static_analysis": static,
                "image_analysis": image, "embedded_urls": list(dict.fromkeys(value[:2048] for value in urls))[:100],
                "archive_members": static.get("archive_members", [])}
        elif task.get("operation") == "url":
            from backend.controlled_fetch import expand_url
            fetched = expand_url(task.get("url", ""))
            result = {"available": "error" not in fetched, **fetched}
        else:
            raise ValueError("unknown_operation")
    encoded = json.dumps(result, ensure_ascii=True).encode()
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("output_limit")
    sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No attacker-controlled error messages or data in the protocol.
        sys.stdout.write('{"available":false,"error":"inspection_failed"}')
