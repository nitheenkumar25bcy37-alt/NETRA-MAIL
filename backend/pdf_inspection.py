"""Bounded PDF extraction. Called only inside a one-shot inspection worker.

No decrypted PDF is written, no actions are executed and no links are visited.
"""
import io
import re

MAX_PAGES = 5
MAX_TEXT = 50000


def inspect_pdf(data, password, *, visual_checks=True):
    from pypdf import PdfReader

    if not data.startswith(b"%PDF-"):
        return {"available": False, "error": "not_pdf"}
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        encrypted = reader.is_encrypted
        if encrypted and not reader.decrypt(password):
            return {"available": False, "error": "incorrect_password"}
        total = len(reader.pages)
    except Exception:
        return {"available": False, "error": "unsupported_or_damaged_pdf"}
    limitations = ["Static inspection cannot certify that a document is safe.",
                  "Embedded files are identified but not opened or executed.",
                  "URLs are checked locally; destinations are not visited."]
    if total > MAX_PAGES:
        limitations.append(f"Only the first {MAX_PAGES} of {total} pages were inspected.")
    # Traverse decrypted PDF objects, including catalog-level actions.
    seen, stack, active, visited = set(), [reader.trailer], set(), 0
    while stack and visited < 10000:
        value = stack.pop()
        if hasattr(value, "idnum"):
            identity = (value.idnum, value.generation)
            if identity in seen:
                continue
            seen.add(identity)
            value = value.get_object()
        visited += 1
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key) in {"/JS", "/JavaScript", "/EmbeddedFiles", "/RichMedia"}:
                    active.add(str(key))
                if str(key) == "/S" and str(child) in {"/Launch", "/SubmitForm", "/GoToR", "/JavaScript"}:
                    active.add(str(child))
                stack.append(child)
        elif isinstance(value, (list, tuple)):
            stack.extend(value[:10000])
    if stack:
        limitations.append("PDF object inspection reached its complexity limit.")
    pages, remaining = [], MAX_TEXT
    renderer = None
    try:
        if not visual_checks:
            raise RuntimeError("visual_checks_deferred")
        import pypdfium2 as pdfium
        renderer = pdfium.PdfDocument(data, password=password or None)
    except Exception:
        limitations.append("Page rendering unavailable; OCR and QR checks could not run.")
    try:
        for number in range(min(total, MAX_PAGES)):
            page = reader.pages[number]
            notes, links = [], []
            try:
                extracted = page.extract_text() or ""
                text = extracted[:remaining]
                if len(extracted) > remaining:
                    notes.append("Text extraction reached its character limit.")
                remaining -= len(text)
            except Exception:
                text = ""
                notes.append("Native text extraction failed.")
            for annotation in (page.get("/Annots") or [])[:100]:
                try:
                    action = annotation.get_object().get("/A")
                    if action is None:
                        continue
                    action = action.get_object()
                    if str(action.get("/S")) == "/URI":
                        links.append(str(action.get("/URI", ""))[:2048])
                except Exception:
                    notes.append("A link annotation could not be decoded.")
            visual = {"available": False, "ocr_available": False, "qr_payloads": []}
            if renderer is not None:
                try:
                    rendered_page = renderer[number]
                    try:
                        width, height = rendered_page.get_size()
                        scale = min(2.0, 1600 / max(width, height))
                        if scale <= 0:
                            raise ValueError("Invalid page size")
                        bitmap = rendered_page.render(scale=scale)
                        try:
                            image = bitmap.to_pil()
                            buffer = io.BytesIO()
                            image.save(buffer, format="PNG")
                            from backend.image_analyzer import analyze_image
                            visual = analyze_image(buffer.getvalue(), "image/png")
                        finally:
                            bitmap.close()
                    finally:
                        rendered_page.close()
                except Exception:
                    notes.append("Page rendering or image analysis could not finish.")
            ocr = str(visual.get("ocr_text", ""))[:remaining]
            remaining -= len(ocr)
            links.extend(re.findall(r"https?://[^\s<>\"']+", text + "\n" + ocr))
            links.extend(visual.get("qr_payloads", []))
            pages.append({"page": number + 1, "text": text + "\n" + ocr,
                          "urls": list(dict.fromkeys(u[:2048] for u in links if u.lower().startswith(("http://", "https://"))))[:50],
                          "ocr_available": bool(visual.get("ocr_available")),
                          "qr_available": bool(visual.get("qr_available", False)),
                          "qr_count": len(visual.get("qr_payloads", [])),
                          "limitations": notes + visual.get("limitations", [])})
    finally:
        if renderer is not None:
            renderer.close()
    return {"available": True, "encrypted": encrypted, "total_pages": total,
            "pages": pages, "active_content": sorted(active), "limitations": limitations}
