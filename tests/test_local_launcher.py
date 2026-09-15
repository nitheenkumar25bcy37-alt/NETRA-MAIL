import json

from backend.local_extension import detect_unpacked_extension_id


def test_detects_only_extension_installed_from_current_project(tmp_path):
    root = tmp_path / "project"
    extension = root / "extension"
    extension.mkdir(parents=True)
    user_data = tmp_path / "User Data"
    profile = user_data / "Profile 1"
    profile.mkdir(parents=True)
    wanted = "p" * 32
    other = "a" * 32
    preferences = {
        "extensions": {"settings": {
            wanted: {"path": str(extension)},
            other: {"path": str(tmp_path / "other" / "extension")},
        }}
    }
    (profile / "Secure Preferences").write_text(json.dumps(preferences), encoding="utf-8")
    assert detect_unpacked_extension_id(root, user_data) == wanted


def test_ambiguous_or_missing_extension_fails_closed(tmp_path):
    root = tmp_path / "project"
    extension = root / "extension"
    extension.mkdir(parents=True)
    user_data = tmp_path / "User Data"
    profile = user_data / "Default"
    profile.mkdir(parents=True)
    settings = {"a" * 32: {"path": str(extension)}, "b" * 32: {"path": str(extension)}}
    (profile / "Secure Preferences").write_text(
        json.dumps({"extensions": {"settings": settings}}), encoding="utf-8")
    assert detect_unpacked_extension_id(root, user_data) == ""
    assert detect_unpacked_extension_id(root, tmp_path / "absent") == ""
