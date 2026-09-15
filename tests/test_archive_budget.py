import io
import zipfile
from unittest.mock import patch

from backend.attachment_analyzer import AttachmentAnalyzer


def test_high_compression_ratio_members_are_not_decompressed():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("compressed.txt", b"a" * (400 * 1024))
    with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("Unsafe decompression")):
        members, urls, encrypted, reasons = AttachmentAnalyzer._archive(stream.getvalue())
    assert members
    assert any("budget" in reason for reason in reasons)
    assert urls == []


def test_archive_size_budget_still_reports_executable_member():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("invoice.exe", b"MZ" + b"a" * (1024 * 1024))
    members, urls, encrypted, reasons = AttachmentAnalyzer._archive(stream.getvalue())
    assert any("executable" in reason for reason in reasons)
