import pytest
from evaluation.manifest_validation import validate_cases


def test_duplicate_content_rejected(tmp_path):
    (tmp_path / "a.eml").write_bytes(b"Subject: one\r\n\r\nHello")
    (tmp_path / "b.eml").write_bytes(b"Subject: one\r\n\r\nHello")
    with pytest.raises(ValueError, match="Duplicate"):
        validate_cases([{"path": "a.eml", "malicious": False}, {"path": "b.eml", "malicious": True}], tmp_path)


@pytest.mark.parametrize("cases", [{}, [], ["bad"], [{"path": "../outside.eml", "malicious": True}]])
def test_invalid_manifest_rejected(cases, tmp_path):
    with pytest.raises(ValueError):
        validate_cases(cases, tmp_path)
