"""Bidi formatting controls must not split credential patterns at LLM/output boundaries."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from translator import heuristic_translate, translate_finding  # noqa: E402


def _client(text):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=text)],
    )
    return client


@pytest.mark.parametrize("marker", ["\u061c", "\u200e", "\u200f", "\u202e", "\u2066", "\u206a"])
def test_bidi_split_token_is_redacted_before_paid_model_and_terminal_output(marker):
    finding = {
        "id": "case-1",
        "severity": "HIGH",
        "description": f"tok{marker}en=secretInEvidence",
    }
    client = _client(f"Rotate tok{marker}en=secretFromProvider")
    result = translate_finding(finding, client)

    sent = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "secretInEvidence" not in sent
    assert "token=[REDACTED]" in sent
    assert "secretFromProvider" not in result.plain_english
    assert "token=[REDACTED]" in result.plain_english
    assert marker not in result.plain_english
    assert marker in finding["description"]  # do not mutate source evidence


def test_bidi_split_signed_url_and_offline_metadata_are_redacted():
    finding = {
        "id": "callback?si\u200fg=shortWebhookSecret&mode=check",
        "severity": "LOW",
        "rule": "ssh_brute_force",
    }
    result = heuristic_translate(finding)
    assert result.finding_id == "callback?sig=[REDACTED]&mode=check"
    assert "shortWebhookSecret" not in result.finding_id


def test_bidi_obfuscated_json_key_is_rejected_before_any_model_call():
    client = _client("Never reached")
    with pytest.raises(ValueError, match="unsafe JSON key"):
        translate_finding({"id": "case-2", "api\u200f_key": "secret"}, client)
    client.messages.create.assert_not_called()


def test_ordinary_multilingual_text_is_preserved():
    result = translate_finding(
        {"id": "case-3", "severity": "LOW", "description": "مراجعة الأذونات"},
        _client("راجع الأذونات اليوم."),
    )
    assert result.plain_english == "راجع الأذونات اليوم."
