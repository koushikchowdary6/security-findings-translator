"""Prevent recognizable credentials from leaking through printed translations."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import heuristic_translate, translate_finding  # noqa: E402


def _client(response_text):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=response_text)],
    )
    return client


def test_claude_result_redacts_metadata_and_provider_text():
    finding = {
        "id": "webhook?sig=shortWebhookSecret&mode=check",
        "severity": "HIGH api_key=metadataSecret",
        "description": "Callback is exposed",
    }
    response = (
        "Ask IT to rotate https://example.invalid/?page=2"
        "&token=shortModelSecret&mode=review."
    )
    result = translate_finding(finding, _client(response))

    for secret in ("shortWebhookSecret", "metadataSecret", "shortModelSecret"):
        assert secret not in (result.finding_id + result.severity + result.plain_english)
    assert "sig=[REDACTED]" in result.finding_id
    assert "mode=check" in result.finding_id
    assert "api_key=[REDACTED]" in result.severity
    assert "token=[REDACTED]" in result.plain_english
    assert "page=2" in result.plain_english
    assert "mode=review" in result.plain_english
    # Source evidence must remain intact for local incident investigation.
    assert "shortWebhookSecret" in finding["id"]
    assert "metadataSecret" in finding["severity"]


def test_offline_translation_redacts_identifiers_and_severity():
    finding = {
        "rule": "ssh_brute_force",
        "id": "case?signature=shortOfflineSecret",
        "severity": "LOW password=shortPassword",
    }
    result = heuristic_translate(finding)
    assert "shortOfflineSecret" not in result.finding_id
    assert "shortPassword" not in result.severity
    assert result.finding_id == "case?signature=[REDACTED]"
    assert "password=[REDACTED]" in result.severity
    assert "Next step:" in result.plain_english


def test_benign_result_text_and_metadata_remain_unchanged():
    finding = {"id": "case-123", "severity": "HIGH"}
    result = translate_finding(
        finding, _client("Ask IT to review page 2 of the access log.")
    )
    assert result.finding_id == "case-123"
    assert result.severity == "HIGH"
    assert result.plain_english == "Ask IT to review page 2 of the access log."
