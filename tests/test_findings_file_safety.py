"""Fail-closed file boundaries for user-supplied security telemetry."""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import MAX_FINDINGS_FILE_BYTES, translate_findings_file  # noqa: E402


def test_rejects_symlink_even_when_target_is_valid_json(tmp_path):
    target = tmp_path / "sensitive.json"
    target.write_text(json.dumps({"id": "private"}), encoding="utf-8")
    link = tmp_path / "input.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="regular file"):
        translate_findings_file(str(link), offline=True)


def test_rejects_directory_before_open(tmp_path):
    with pytest.raises(ValueError, match="regular file"):
        translate_findings_file(str(tmp_path), offline=True)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_rejects_fifo_without_blocking(tmp_path):
    pipe = tmp_path / "findings.pipe"
    os.mkfifo(pipe)
    with pytest.raises(ValueError, match="regular file"):
        translate_findings_file(str(pipe), offline=True)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_rejects_fifo_swapped_between_lstat_and_open(tmp_path, monkeypatch):
    path = tmp_path / "findings.json"
    path.write_text('{"id": "original"}', encoding="utf-8")
    real_open = os.open

    def swap_then_open(filename, flags, *args, **kwargs):
        path.unlink()
        os.mkfifo(path)
        # O_NONBLOCK is essential here: opening a FIFO for reading otherwise
        # hangs before the post-open descriptor validation can run.
        assert flags & os.O_NONBLOCK
        return real_open(filename, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_then_open)
    with pytest.raises(ValueError, match="regular file"):
        translate_findings_file(str(path), offline=True)


def test_accepts_exact_byte_budget_with_valid_json(tmp_path):
    payload = b'{"id":"ok"}'
    path = tmp_path / "max.json"
    path.write_bytes(payload + b" " * (MAX_FINDINGS_FILE_BYTES - len(payload)))
    result = translate_findings_file(str(path), offline=True)
    assert len(result) == 1
    assert result[0].finding_id == "ok"
