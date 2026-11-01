"""AWS/cloud credential evidence must not reach an external LLM or terminal logs."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import _serialized_finding_evidence, translate_finding


def _client(response="Ask IT to rotate the credential."):
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=response)],
    )
    return client


@pytest.mark.parametrize("parameter,secret", [
    ("AWSSecretAccessKey", "shortAwsSecret"),
    ("aws_secret_access_key", "anotherShortSecret"),
    ("AWSSessionToken", "opaqueSession"),
    ("X-Amz-Credential", "ASIAEXAMPLE%2F20261101%2Fus-east-1%2Fs3"),
    ("X-Goog-Credential", "service-account%40example.invalid%2Fscope"),
])
def test_sensitive_cloud_query_parameters_redacted_before_paid_call(parameter, secret):
    finding = {
        "id": "case",
        "description": (
            "https://storage.example.invalid/object?mode=read&"
            f"{parameter}={secret}&page=2"
        ),
    }
    client = _client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs["messages"][0]["content"]

    assert secret not in prompt
    assert f"{parameter}=[REDACTED]" in prompt
    assert "mode=read" in prompt and "page=2" in prompt
    assert secret in finding["description"]  # Local evidence is not mutated.


@pytest.mark.parametrize("label,secret", [
    ("AWS_SECRET_ACCESS_KEY", "shortPlainSecret"),
    ("awsSecretAccessKey", "anotherPlainSecret"),
    ("aws_session_token", "sessionShortValue"),
    ("awsSessionToken", "sessionCamelValue"),
])
def test_plain_text_aws_secret_assignments_redacted_in_model_evidence(label, secret):
    finding = {"id": "case", "details": f"environment {label}={secret}"}
    serialized = json.loads(_serialized_finding_evidence(finding))
    assert secret not in serialized["details"]
    assert "[REDACTED]" in serialized["details"]
    assert finding["details"].endswith(secret)


def test_cloud_credentials_also_redacted_in_model_output_and_finding_id():
    secret = "shortCloudToken"
    url = "https://example.invalid/?X-Amz-Credential=" + secret
    client = _client("Provider repeated " + url)
    result = translate_finding({"id": url, "description": "expired link"}, client)

    assert secret not in result.finding_id
    assert secret not in result.plain_english
    assert "X-Amz-Credential=[REDACTED]" in result.finding_id
    assert "X-Amz-Credential=[REDACTED]" in result.plain_english


def test_noncredential_query_parameters_and_text_remain_available_for_triage():
    finding = {
        "id": "case",
        "description": "https://example.invalid/?X-Amz-Date=20261101T120000Z&mode=read",
        "metadata": {"region": "us-east-1", "status": "expired"},
    }
    assert json.loads(_serialized_finding_evidence(finding)) == finding
