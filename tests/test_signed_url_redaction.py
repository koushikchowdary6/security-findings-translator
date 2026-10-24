"""Signed URL credentials must not cross the external LLM request boundary."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import translate_finding  # noqa: E402


def _fake_client():
    client = MagicMock()
    client.messages.create.return_value.content = [
        type("TextBlock", (), {"type": "text", "text": "Ask IT to rotate the link."})()
    ]
    return client


def test_signed_webhook_and_api_query_tokens_are_redacted_before_claude():
    callback = (
        "https://example.invalid/workflows/abc/triggers/manual/paths/invoke"
        "?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun"
        "&sv=1.0&sig=shortKnownSecret"
    )
    finding = {
        "id": "webhook-1",
        "description": "Callback found in pipeline: " + callback,
        "nested": [
            "https://api.example.invalid/endpoint?token=anotherLowEntropySecret&mode=check",
            "https://api.example.invalid/endpoint?signature=abc123&api_key=shortKey",
        ],
    }
    client = _fake_client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]

    for secret in ("shortKnownSecret", "anotherLowEntropySecret", "abc123", "shortKey"):
        assert secret not in prompt
    for preserved in ("api-version=2016-10-01", "sp=%2Ftriggers%2Fmanual%2Frun",
                      "sv=1.0", "mode=check", "sig=[REDACTED]",
                      "token=[REDACTED]", "signature=[REDACTED]",
                      "api_key=[REDACTED]"):
        assert preserved in prompt
    # Sanitization must not destroy the original local incident evidence.
    assert "shortKnownSecret" in finding["description"]


def test_benign_url_parameters_remain_intact():
    finding = {
        "description": (
            "Request https://example.invalid/?page=2&sort=desc&mode=preview "
            "had a timeout."
        ),
    }
    client = _fake_client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "page=2&sort=desc&mode=preview" in prompt
    assert "[REDACTED]" not in prompt
