"""
Tests for the translation logic.

The Claude API call is mocked so these run offline and don't require a real
key or cost tokens. The heuristic (offline) backend is tested directly.
"""
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from translator import (  # noqa: E402
    translate_finding,
    heuristic_translate,
    translate_findings_file,
)


class FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class FakeResponse:
    def __init__(self, text):
        self.content = [FakeTextBlock(text)]


def make_fake_client(reply_text: str):
    client = MagicMock()
    client.messages.create.return_value = FakeResponse(reply_text)
    return client


# --- Claude path (mocked) ------------------------------------------------------

def test_translate_finding_returns_expected_fields():
    finding = {"id": "iam-001", "severity": "HIGH", "rule": "privilege_escalation_action"}
    client = make_fake_client(
        "This finding means someone could give themselves more access than "
        "they should have. Fix: review who can change IAM policies."
    )
    result = translate_finding(finding, client)
    assert result.finding_id == "iam-001"
    assert result.severity == "HIGH"
    assert "access" in result.plain_english.lower()


def test_translate_finding_calls_api_with_finding_json():
    finding = {"id": "ssh-002", "severity": "CRITICAL", "rule": "successful_login_after_bruteforce"}
    client = make_fake_client("Someone guessed a password and got in. Reset that password now.")
    translate_finding(finding, client)
    call_kwargs = client.messages.create.call_args.kwargs
    assert "ssh-002" in call_kwargs["messages"][0]["content"]
    assert call_kwargs["system"]


def test_translate_finding_handles_missing_id_falls_back_to_rule():
    finding = {"rule": "root_login_attempt", "severity": "MEDIUM"}
    client = make_fake_client("Someone tried to log in directly as the most powerful account.")
    result = translate_finding(finding, client)
    assert result.finding_id == "root_login_attempt"


# --- Offline heuristic path ----------------------------------------------------

def test_heuristic_known_rule_is_plain_and_actionable():
    finding = {"id": "iam-001", "severity": "HIGH", "rule": "privilege_escalation_action"}
    r = heuristic_translate(finding)
    text = r.plain_english.lower()
    assert "next step" in text          # always gives one concrete action
    assert "iam" not in text            # no unexplained jargon
    assert r.severity == "HIGH"


def test_heuristic_unknown_rule_has_safe_fallback():
    r = heuristic_translate({"id": "x", "severity": "LOW", "rule": "some_new_rule"})
    assert "next step" in r.plain_english.lower()


def test_heuristic_severity_prefix_reflects_urgency():
    crit = heuristic_translate({"rule": "ssh_brute_force", "severity": "CRITICAL"})
    low = heuristic_translate({"rule": "ssh_brute_force", "severity": "LOW"})
    assert crit.plain_english != low.plain_english
    assert crit.plain_english.lower().startswith("this is urgent")


def test_offline_file_translation_end_to_end(tmp_path):
    import json
    p = tmp_path / "f.json"
    p.write_text(json.dumps([
        {"id": "a", "severity": "HIGH", "rule": "privilege_escalation_action"},
        {"id": "b", "severity": "CRITICAL", "rule": "successful_login_after_bruteforce"},
    ]))
    results = translate_findings_file(str(p), offline=True)
    assert len(results) == 2
    assert all("next step" in r.plain_english.lower() for r in results)


def test_offline_file_translation_rejects_scalar_json(tmp_path):
    import json

    p = tmp_path / "bad.json"
    p.write_text(json.dumps("not-a-finding"), encoding="utf-8")

    try:
        translate_findings_file(str(p), offline=True)
    except ValueError as exc:
        assert "object or an array of objects" in str(exc)
    else:
        raise AssertionError("scalar JSON should be rejected")


def test_offline_file_translation_rejects_mixed_array(tmp_path):
    import json

    p = tmp_path / "mixed.json"
    p.write_text(
        json.dumps([
            {"id": "ok", "severity": "LOW", "rule": "ssh_brute_force"},
            "not-a-finding",
        ]),
        encoding="utf-8",
    )

    try:
        translate_findings_file(str(p), offline=True)
    except ValueError as exc:
        assert "object or an array of objects" in str(exc)
    else:
        raise AssertionError("mixed finding arrays should be rejected")
