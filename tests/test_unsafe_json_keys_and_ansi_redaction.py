"""Credential-bearing JSON keys and ANSI-split tokens must not leak to LLMs or logs."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import translate_finding, translate_findings_file  # noqa: E402


def _client(text="Ask IT to review the incident."):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=text)],
    )
    return client


@pytest.mark.parametrize("unsafe_key", [
    "callback?sig=shortWebhookSecret",
    "authorization: Bearer privateCredential",
    "api_\x1b[31mkey=splitSecret",
])
def test_unsafe_nested_json_keys_rejected_before_paid_call(unsafe_key):
    client = _client()
    finding = {"id": "case", "metadata": {unsafe_key: "observed"}}
    with pytest.raises(ValueError, match="unsafe JSON key"):
        translate_finding(finding, client)
    client.messages.create.assert_not_called()
    assert unsafe_key in finding["metadata"]  # No source mutation.


def test_unsafe_key_in_later_batch_record_rejected_during_preflight(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([
        {"id": "valid", "rule": "ssh_brute_force"},
        {"id": "unsafe", "metadata": {"url?token=privateValue": "event"}},
    ]), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe JSON key"):
        translate_findings_file(str(path), offline=True)


def test_ansi_split_secret_is_redacted_in_model_evidence_and_provider_output():
    finding = {
        "id": "case-ansi",
        "description": "Exposed api_\x1b[31mkey=secretFromTelemetry",
        "metadata": {"status": "needs review"},
    }
    client = _client("Rotate api_\x1b[32mkey=secretFromProvider promptly.")
    result = translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "secretFromTelemetry" not in prompt
    assert "secretFromProvider" not in result.plain_english
    assert "Exposed [REDACTED]" in prompt
    assert "Rotate [REDACTED] promptly." == result.plain_english
    assert "needs review" in prompt
    assert "\x1b[31m" in finding["description"]


def test_benign_nested_keys_and_text_remain_unchanged():
    client = _client("Ask IT to review the alert.")
    finding = {"id": "case", "metadata": {"source_ip": "192.0.2.5", "event_count": 4}}
    result = translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert '"source_ip": "192.0.2.5"' in prompt
    assert '"event_count": 4' in prompt
    assert result.plain_english == "Ask IT to review the alert."
