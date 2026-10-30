"""Untrusted finding metadata and model output must not forge terminal logs."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from translator import heuristic_translate, translate_finding


def _client(text):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=text)],
    )
    return client


def test_finding_metadata_cannot_forge_severity_or_new_log_line():
    finding = {
        "id": "case-123\\n[CRITICAL] fake incident\\x1b[31m",
        "severity": "LOW\\u202eHIGH\\x1b[0m",
        "rule": "ssh_brute_force",
    }
    result = heuristic_translate(finding)
    assert result.finding_id == "case-123 [CRITICAL] fake incident"
    assert result.severity == "LOW HIGH"
    assert "\\n" not in result.finding_id
    assert "\\x1b" not in result.finding_id + result.severity
    assert "\\u202e" not in result.severity
    assert "\\n" in finding["id"]  # original evidence is untouched


def test_provider_response_is_terminal_safe_and_still_redacts_secrets():
    response = "Review this issue.\\x1b[31m\\n[CRITICAL] spoofed\\u2066\\x1b[0m token=shortSecret"
    result = translate_finding(
        {"id": "finding-1", "severity": "HIGH"}, _client(response)
    )
    assert "\\x1b" not in result.plain_english
    assert "\\n" not in result.plain_english
    assert "\\u2066" not in result.plain_english
    assert "shortSecret" not in result.plain_english
    assert "[REDACTED]" in result.plain_english
    assert result.plain_english.startswith("Review this issue.")


def test_benign_prose_is_not_changed():
    result = translate_finding(
        {"id": "case-42", "severity": "MEDIUM"},
        _client("Ask IT to review the access policy."),
    )
    assert result.finding_id == "case-42"
    assert result.severity == "MEDIUM"
    assert result.plain_english == "Ask IT to review the access policy."
