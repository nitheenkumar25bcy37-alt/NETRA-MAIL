"""Bounded QR and OCR extraction from common raster image attachments."""
import io
import re

_rapid_engine = None


def _portable_ocr(data):
    global _rapid_engine
    from rapidocr_onnxruntime import RapidOCR
    if _rapid_engine is None:
        _rapid_engine = RapidOCR()
    lines, _ = _rapid_engine(data)
    return "\n".join(str(line[1]) for line in (lines or [])[:200] if len(line) > 1)[:10000]


def analyze_image(data: bytes, content_type: str) -> dict:
    result = {"available": False, "qr_payloads": [], "ocr_text": "", "ocr_available": False, "limitations": []}
    if not content_type.lower().startswith("image/") or not data or len(data) > 5 * 1024 * 1024:
        return result
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as source:
            if source.width * source.height > 20_000_000 or max(source.size) > 10000:
                result["limitations"].append("Image dimensions exceed safe inspection limits.")
                return result
            source.verify()
        with Image.open(io.BytesIO(data)) as source:
            if getattr(source, "n_frames", 1) > 1:
                result["limitations"].append("Only the first image frame was inspected.")
            source.thumbnail((1600, 1600))
            image = source.convert("RGB")
        # Native decoders receive the bounded raster, never the original bytes.
        normalized = io.BytesIO()
        image.save(normalized, format="PNG")
        result["available"] = True
    except Exception:
        result["limitations"].append("Image could not be safely decoded.")
        return result
    try:
        import cv2, numpy as np
        matrix = np.asarray(image.convert("L"))
        detector = cv2.QRCodeDetector()
        found, decoded, _, _ = detector.detectAndDecodeMulti(matrix)
        values = list(decoded) if found else [detector.detectAndDecode(matrix)[0]]
        if not any(values) and min(matrix.shape[:2]) < 300:
            bordered = cv2.copyMakeBorder(matrix, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=255)
            scale = min(4, 1600 / max(bordered.shape[:2]))
            enlarged = cv2.resize(bordered, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
            values = [detector.detectAndDecode(enlarged)[0]]
        result["qr_payloads"] = [value[:2048] for value in values if value][:20]
    except Exception:
        result["limitations"].append("QR decoder unavailable or unable to decode this image.")
    try:
        try:
            text = _portable_ocr(normalized.getvalue())
        except ImportError:
            import pytesseract
            text = pytesseract.image_to_string(image, timeout=3)[:10000]
        result["ocr_text"] = re.sub(r"\x00", "", text)
        result["ocr_available"] = True
        result["limitations"].append("OCR language coverage depends on the bundled model; Indian-language text may be missed and is not validated.")
    except Exception:
        result["limitations"].append("OCR runtime was unavailable or could not decode this image; QR and image structure checks still ran.")
    return result
