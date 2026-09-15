import io
import struct
import zlib

import cv2
import numpy as np
import pytest
from PIL import Image
from backend import image_analyzer as analyzer


def png(image):
    output = io.BytesIO()
    image.save(output, "PNG")
    return output.getvalue()


@pytest.fixture(autouse=True)
def stub_ocr(monkeypatch):
    monkeypatch.setattr(analyzer, "_portable_ocr", lambda data: "")


@pytest.mark.parametrize("rotation", [0, 90, 180, 270])
@pytest.mark.parametrize("target", ["https://example.test/help", "https://credential-lure.invalid/login"])
def test_rotated_qr(rotation, target):
    matrix = cv2.QRCodeEncoder_create().encode(target)
    image = Image.fromarray(matrix).resize((240, 240), Image.Resampling.NEAREST)
    result = analyzer.analyze_image(png(image.rotate(rotation)), "image/png")
    assert target in result["qr_payloads"]


def test_noisy_qr():
    target = "https://example.test/help"
    matrix = cv2.QRCodeEncoder_create().encode(target)
    image = Image.fromarray(matrix).resize((300, 300), Image.Resampling.NEAREST)
    noise = np.random.default_rng(7).integers(-12, 13, (300, 300))
    image = Image.fromarray(np.clip(np.asarray(image).astype(int) + noise, 0, 255).astype(np.uint8))
    assert target in analyzer.analyze_image(png(image), "image/png")["qr_payloads"]


def test_native_decoders_only_receive_bounded_raster(monkeypatch):
    observed = {}
    def ocr(data):
        with Image.open(io.BytesIO(data)) as image:
            observed["ocr"] = image.size
        return "LOGIN"
    class Detector:
        def detectAndDecodeMulti(self, matrix):
            observed["qr"] = matrix.shape
            return True, ["https://example.test"], None, None
    monkeypatch.setattr(analyzer, "_portable_ocr", ocr)
    monkeypatch.setattr(cv2, "QRCodeDetector", Detector)
    result = analyzer.analyze_image(png(Image.new("RGB", (4000, 2000))), "image/png")
    assert observed == {"ocr": (1600, 800), "qr": (800, 1600)}
    assert result["ocr_text"] == "LOGIN"


@pytest.mark.parametrize("data", [b"corrupt", b"x" * (5 * 1024 * 1024 + 1)], ids=["corrupt", "oversized"])
def test_invalid_bytes_never_reach_ocr(monkeypatch, data):
    def fail(data):
        pytest.fail("Invalid image reached OCR")
    monkeypatch.setattr(analyzer, "_portable_ocr", fail)
    assert analyzer.analyze_image(data, "image/png")["available"] is False


def test_oversized_header_rejected_before_verification(monkeypatch):
    data = bytearray(png(Image.new("RGB", (1, 1))))
    data[16:24] = struct.pack(">II", 10001, 1)
    data[29:33] = struct.pack(">I", zlib.crc32(data[12:29]))
    result = analyzer.analyze_image(bytes(data), "image/png")
    assert result["available"] is False
    assert "dimensions" in result["limitations"][0]


def test_animated_image_reports_partial_inspection():
    output = io.BytesIO()
    Image.new("RGB", (20, 20), "white").save(output, "GIF", save_all=True,
        append_images=[Image.new("RGB", (20, 20), "black")])
    result = analyzer.analyze_image(output.getvalue(), "image/gif")
    assert result["available"] is True
    assert "Only the first image frame was inspected." in result["limitations"]
