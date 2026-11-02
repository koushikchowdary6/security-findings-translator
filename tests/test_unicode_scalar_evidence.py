"""Malformed Unicode must not reach a paid provider or break terminal output."""

from types import SimpleNamespace

import pytest

from src.translator import (
    _safe_output_text,
    _serialized_finding_evidence,
    translate_finding,
)


class RejectCalls:
    def __init__(self):
        self.calls = 0
        self.messages = SimpleNamespace(create=self.create)

    def create(self, **kwargs):
        self.calls += 1
        raise AssertionError("invalid evidence must not reach the model")


@pytest.mark.parametrize("finding", [
    {"id": "case", "detail": "bad" + chr(0xD800)},
    {"id": "case", "nested": [{"description": "bad" + chr(0xDFFF)}]},
    {"id": "case", "bad" + chr(0xD800) + "key": "value"},
    {"id": "bad" + chr(0xD800), "detail": "ordinary"},
])
def test_invalid_unicode_scalar_fails_before_paid_model_call(finding):
    client = RejectCalls()
    with pytest.raises(ValueError, match="Unicode surrogate|unsafe JSON key"):
        translate_finding(finding, client)
    assert client.calls == 0


def test_terminal_output_replaces_surrogates_without_dropping_adjacent_evidence():
    result = _safe_output_text("case:" + chr(0xD800) + " valid " + chr(0xDFFF))
    assert result == "case:[INVALID_UNICODE] valid [INVALID_UNICODE]"
    result.encode("utf-8", errors="strict")


def test_valid_supplementary_unicode_remains_in_llm_evidence_and_output():
    finding = {"id": "case-😀", "description": "valid supplementary glyph 𐍈"}
    serialized = _serialized_finding_evidence(finding)
    assert "case-" in serialized
    assert "description" in serialized
    assert _safe_output_text("case-😀") == "case-😀"
