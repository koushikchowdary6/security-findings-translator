"""Fail-closed contracts for security evidence sent to a paid LLM."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import MAX_FINDING_JSON_CHARS, translate_finding, translate_findings_file


@pytest.mark.parametrize("raw", [
    '{"id": "first", "id": "second", "rule": "ssh_brute_force"}',
    '{"id": "case", "metadata": {"severity": "LOW", "severity": "HIGH"}}',
    '[{"rule": "a"}, {"rule": "b", "rule": "c"}]',
])
def test_duplicate_json_keys_rejected_before_offline_translation(tmp_path, raw):
    path = tmp_path / "ambiguous.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate finding JSON key"):
        translate_findings_file(str(path), offline=True)


@pytest.mark.parametrize("raw", [
    '{"score": NaN}',
    '{"score": Infinity}',
    '{"score": -Infinity}',
    '{"score": 1e999}',
    '{"nested": [0, -1e999]}',
])
def test_nonfinite_json_values_rejected_before_translation(tmp_path, raw):
    path = tmp_path / "invalid.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        translate_findings_file(str(path), offline=True)


def test_valid_nested_finding_json_still_translates_offline(tmp_path):
    path = tmp_path / "valid.json"
    path.write_text(
        '[{"id":"one","severity":"LOW","rule":"ssh_brute_force",'
        '"metadata":{"count":2.5}},{"id":"two","rule":"unknown"}]',
        encoding="utf-8",
    )
    results = translate_findings_file(str(path), offline=True)
    assert [item.finding_id for item in results] == ["one", "two"]


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), object()])
def test_direct_api_translation_rejects_invalid_evidence_before_network(bad):
    client = MagicMock()
    with pytest.raises(ValueError, match="JSON-serializable and finite"):
        translate_finding({"id": "case", "measurement": bad}, client)
    client.messages.create.assert_not_called()


def test_oversized_finding_rejected_before_paid_api_call():
    client = MagicMock()
    with pytest.raises(ValueError, match="size limit"):
        translate_finding({"id": "case", "description": "x" * (MAX_FINDING_JSON_CHARS + 1)}, client)
    client.messages.create.assert_not_called()


def test_small_valid_finding_still_reaches_model():
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text="Ask IT to review access.")],
    )
    result = translate_finding({"id": "case", "severity": "MEDIUM"}, client)
    assert result.plain_english == "Ask IT to review access."
    client.messages.create.assert_called_once()
