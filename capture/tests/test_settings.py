import json

import pytest

from capture import settings
from capture.interfaces import CaptureError, CaptureInterface


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "select_interface", lambda name: CaptureInterface(name, name, "", ()))
    monkeypatch.setattr(settings, "validate_filter", lambda bpf, iface: bpf)


def test_save_reload_and_apply_new_session(tmp_path, configured):
    path = tmp_path / "settings.json"
    expected = settings.save_settings(path, "ethernet-lab", "tcp port 80")
    assert settings.load_settings(path) == expected
    class Manager:
        def start(self, interface, bpf, name):
            return interface, bpf, name
    assert settings.start_saved(Manager(), path, "new") == ("ethernet-lab", "tcp port 80", "new")


@pytest.mark.parametrize("contents", ['{', '[]', '{"version":2}', '{"version":1}'])
def test_bad_settings_actionable(tmp_path, contents, configured):
    path = tmp_path / "settings.json"
    path.write_text(contents)
    with pytest.raises(CaptureError):
        settings.load_settings(path)


def test_saved_interface_revalidated_and_bad_save_preserves_old_file(tmp_path, configured, monkeypatch):
    path = tmp_path / "settings.json"
    settings.save_settings(path, "wifi-lab")
    original = path.read_bytes()
    def missing(_):
        raise CaptureError("Interface unavailable")
    monkeypatch.setattr(settings, "select_interface", missing)
    with pytest.raises(CaptureError, match="unavailable"):
        settings.load_settings(path)
    with pytest.raises(CaptureError, match="unavailable"):
        settings.save_settings(path, "missing")
    assert path.read_bytes() == original


def test_invalid_saved_filter_rejected(tmp_path, configured, monkeypatch):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"version": 1, "interface": "lab", "filter": "invalid"}))
    def invalid(*_):
        raise CaptureError("Invalid BPF filter")
    monkeypatch.setattr(settings, "validate_filter", invalid)
    with pytest.raises(CaptureError, match="Invalid BPF"):
        settings.load_settings(path)
