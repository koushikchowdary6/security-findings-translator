"""Bound batch parsing and preflight all evidence before a paid LLM request."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import (  # noqa: E402
    MAX_FINDING_JSON_CHARS,
    MAX_FINDINGS_FILE_BYTES,
    MAX_FINDINGS_PER_BATCH,
    translate_findings_file,
)


def test_file_byte_limit_rejects_oversized_json_before_parsing(tmp_path):
    path = tmp_path / "huge.json"
    path.write_bytes(b" " * (MAX_FINDINGS_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="file exceeds size limit"):
        translate_findings_file(str(path), offline=True)


def test_batch_limit_rejects_many_small_findings(tmp_path):
    path = tmp_path / "too_many.json"
    path.write_text(json.dumps([{"id": str(i)} for i in range(MAX_FINDINGS_PER_BATCH + 1)]))
    with pytest.raises(ValueError, match="batch limit"):
        translate_findings_file(str(path), offline=True)


@pytest.mark.parametrize(
    "invalid",
    [
        {"rule": ["ssh_brute_force"]},
        {"severity": {"nested": "HIGH"}},
        {"id": 123},
        {"description": "x" * (MAX_FINDING_JSON_CHARS + 1)},
    ],
)
def test_invalid_later_finding_prevents_all_paid_calls(tmp_path, monkeypatch, invalid):
    path = tmp_path / "batch.json"
    path.write_text(json.dumps([{"id": "valid", "rule": "ssh_brute_force"}, invalid]))
    client_factory = MagicMock()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-test-key")
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=client_factory))
    with pytest.raises(ValueError, match="must be a string|size limit"):
        translate_findings_file(str(path), offline=False)
    client_factory.assert_not_called()


def test_valid_batch_remains_usable_offline(tmp_path):
    path = tmp_path / "valid.json"
    path.write_text(json.dumps([
        {"id": "one", "rule": "ssh_brute_force", "severity": "HIGH"},
        {"id": "two", "rule": "unknown", "severity": "LOW"},
    ]))
    results = translate_findings_file(str(path), offline=True)
    assert [item.finding_id for item in results] == ["one", "two"]
