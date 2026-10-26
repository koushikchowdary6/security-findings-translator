"""Only complete, nonempty Claude replies can be shown as remediation advice."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import translate_finding


def fake_client(stop_reason, text):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason=stop_reason,
        content=[SimpleNamespace(type="text", text=text)],
    )
    return client


@pytest.mark.parametrize("stop_reason", [
    "max_tokens", "tool_use", "pause_turn", "stop_sequence", None,
])
def test_nonfinal_translation_is_not_returned_as_actionable_advice(stop_reason):
    client = fake_client(stop_reason, "Ask IT to review the")
    with pytest.raises(RuntimeError, match="did not complete normally"):
        translate_finding({"id": "case-1", "severity": "HIGH"}, client)
    assert client.messages.create.call_count == 1


@pytest.mark.parametrize("text", ["", " \n\t "])
def test_empty_completed_translation_is_rejected(text):
    client = fake_client("end_turn", text)
    with pytest.raises(RuntimeError, match="contained no text"):
        translate_finding({"id": "case-2"}, client)


def test_completed_translation_is_returned_without_changing_finding():
    finding = {"id": "case-3", "severity": "MEDIUM"}
    result = translate_finding(finding, fake_client("end_turn", "  Ask IT to verify access. \n"))
    assert result.finding_id == "case-3"
    assert result.severity == "MEDIUM"
    assert result.plain_english == "Ask IT to verify access."
    assert finding == {"id": "case-3", "severity": "MEDIUM"}


@pytest.mark.parametrize("blocks", [
    [],
    [SimpleNamespace(type="text", text="Fix access."),
     SimpleNamespace(type="text", text="Ignore that advice.")],
    [SimpleNamespace(type="tool_use", text="Fix access.")],
    [SimpleNamespace(type="text", text="Fix access."),
     SimpleNamespace(type="tool_use", text="dangerous")],
    [SimpleNamespace(type="text", text=123)],
    [SimpleNamespace(type="text")],
])
def test_ambiguous_or_nontext_completed_responses_are_rejected(blocks):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn", content=blocks,
    )
    with pytest.raises(RuntimeError, match="ambiguous|non-text|no text"):
        translate_finding({"id": "case-4", "severity": "HIGH"}, client)


def test_single_completed_text_block_still_works():
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=(SimpleNamespace(type="text", text="  Review access controls.  "),),
    )
    assert translate_finding({"id": "case-5"}, client).plain_english == "Review access controls."
