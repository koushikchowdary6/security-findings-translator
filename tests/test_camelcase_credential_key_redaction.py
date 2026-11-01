"""Credential field naming conventions must not bypass paid-model redaction."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import _serialized_finding_evidence, translate_finding


def _client():
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text="Ask IT to rotate credentials.")],
    )
    return client


@pytest.mark.parametrize("key", [
    "accessToken", "refreshToken", "sessionToken", "clientSecret",
    "awsSecretAccessKey", "apiKey", "X-Api-Key", "backupAccessToken",
    "secondaryClientSecret", "service_password", "servicePassword",
    "credentials", "aws_secret_access_key",
])
def test_credential_key_variants_are_redacted_before_paid_call(key):
    secret = "synthetic-value-that-must-not-leave"
    finding = {
        "id": "case",
        "metadata": {"nested": {key: secret}, "region": "us-west-2"},
    }
    client = _client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]
    assert secret not in prompt
    assert f'"{key}": "[REDACTED]"' in prompt
    assert '"region": "us-west-2"' in prompt
    assert finding["metadata"]["nested"][key] == secret


def test_unrelated_camelcase_telemetry_is_not_discarded():
    finding = {"id": "case", "metadata": {
        "accessType": "read-only", "sessionDuration": 45, "tokenizerMode": "unicode",
    }}
    serialized = _serialized_finding_evidence(finding)
    parsed = json.loads(serialized)
    assert parsed == finding


@pytest.mark.parametrize("invalid", [
    None, "not-a-finding", [], [{"id": "case"}], 17, True,
])
def test_direct_api_rejects_nonobject_evidence_before_paid_call(invalid):
    client = _client()
    with pytest.raises(ValueError, match="JSON object"):
        translate_finding(invalid, client)
    client.messages.create.assert_not_called()
