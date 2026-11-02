"""URI userinfo and connection strings must stay out of paid-model prompts and logs."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from translator import _serialized_finding_evidence, translate_finding


def _client(response="Ask IT to rotate the connection password."):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=response)],
    )
    return client


@pytest.mark.parametrize("uri,host", [
    ("postgresql://analyst:shortPW@db.example.invalid:5432/reports", "db.example.invalid"),
    ("https://robot:tok123@api.example.invalid/v1", "api.example.invalid"),
    ("redis://:shortPW@cache.example.invalid/0", "cache.example.invalid"),
    ("jdbc:postgresql://service:password@db.example.invalid:5432/app", "db.example.invalid"),
])
def test_credentialed_uri_in_description_redacted_before_provider_call(uri, host):
    finding = {"id": "case", "description": "Observed " + uri}
    client = _client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "://[REDACTED]@" in prompt
    assert host in prompt
    assert uri not in prompt
    assert finding["description"].endswith(uri)  # Preserve original local evidence.


@pytest.mark.parametrize("field", [
    "connectionString", "primaryConnectionString", "dbUrl", "databaseURL",
    "databaseUri", "jdbcUrl", "dsn", "mongoDbUri", "redisUrl", "brokerUrl",
])
def test_connection_metadata_redacted_even_for_nonstandard_secret(field):
    secret = "synthetic-short-password"
    finding = {"id": "case", "metadata": {field: secret, "region": "us-west-2"}}
    serialized = json.loads(_serialized_finding_evidence(finding))
    assert serialized["metadata"][field] == "[REDACTED]"
    assert serialized["metadata"]["region"] == "us-west-2"
    assert finding["metadata"][field] == secret


def test_uri_without_userinfo_and_benign_documentation_url_are_preserved():
    finding = {"description": "https://db.example.invalid:5432/status",
               "documentationUrl": "https://docs.example.invalid/guide"}
    assert json.loads(_serialized_finding_evidence(finding)) == finding


def test_at_sign_in_path_is_not_mistaken_for_url_userinfo():
    finding = {"description": "https://example.invalid/users/alice:member@team"}
    assert json.loads(_serialized_finding_evidence(finding)) == finding


def test_returned_model_text_and_finding_id_also_redact_uri_credentials():
    uri = "postgresql://analyst:shortPW@db.example.invalid:5432/reports"
    client = _client("Found " + uri)
    result = translate_finding({"id": uri, "description": "connection error"}, client)
    assert "shortPW" not in result.finding_id
    assert "shortPW" not in result.plain_english
    assert "://[REDACTED]@" in result.finding_id
    assert "://[REDACTED]@" in result.plain_english


@pytest.mark.parametrize("uri,secret,host", [
    ("https://short-token@api.example.invalid/v1", "short-token", "api.example.invalid"),
    ("postgresql://robot@db.example.invalid/reports", "robot", "db.example.invalid"),
    ("https://name@opaque-key@api.example.invalid/v1", "name@opaque-key", "api.example.invalid"),
])
def test_userinfo_without_password_colon_redacted_before_paid_request(uri, secret, host):
    finding = {"id": "case", "description": "Observed " + uri}
    client = _client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert "://[REDACTED]@" in prompt
    assert host in prompt
    assert secret not in prompt
    assert finding["description"].endswith(uri)


def test_token_only_userinfo_is_redacted_from_display_boundaries():
    uri = "https://short-secret@api.example.invalid/status"
    client = _client("Observed " + uri)
    result = translate_finding({"id": uri, "description": "connection failed"}, client)
    assert "short-secret" not in result.finding_id
    assert "short-secret" not in result.plain_english
    assert "://[REDACTED]@api.example.invalid" in result.finding_id
    assert "://[REDACTED]@api.example.invalid" in result.plain_english


def test_path_and_query_at_signs_remain_intact_without_authority_userinfo():
    finding = {
        "description": "https://example.invalid/users/alice@team",
        "documentationUrl": "https://example.invalid/help?contact=alice@team",
    }
    assert json.loads(_serialized_finding_evidence(finding)) == finding
