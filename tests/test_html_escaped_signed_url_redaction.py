"""HTML-escaped signed URLs must not leak credentials to a provider or logs."""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from translator import translate_finding, heuristic_translate


def _client():
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        stop_reason='end_turn',
        content=[SimpleNamespace(type='text', text='Ask IT to rotate the link.')],
    )
    return client


def test_html_escaped_query_delimiters_are_redacted_before_provider():
    url = ('https://example.invalid/hook?page=2'
           '&amp;sig=shortSecretOne'
           '&#38;token=shortSecretTwo'
           '&#x26;X-Amz-Signature=shortSecretThree'
           '&mode=check')
    finding = {'id': 'case-1', 'description': url}
    client = _client()
    translate_finding(finding, client)
    prompt = client.messages.create.call_args.kwargs['messages'][0]['content']
    for secret in ('shortSecretOne', 'shortSecretTwo', 'shortSecretThree'):
        assert secret not in prompt
    for retained in ('page=2', '&amp;sig=[REDACTED]',
                     '&#38;token=[REDACTED]',
                     '&#x26;X-Amz-Signature=[REDACTED]', '&mode=check'):
        assert retained in prompt
    assert 'shortSecretOne' in finding['description']


def test_html_escaped_signed_url_is_redacted_in_finding_id():
    finding = {'id': 'callback?mode=test&amp;sig=shortSecretFour',
               'severity': 'LOW', 'rule': 'ssh_brute_force'}
    result = heuristic_translate(finding)
    assert 'shortSecretFour' not in result.finding_id
    assert 'mode=test&amp;sig=[REDACTED]' in result.finding_id


def test_benign_html_escaped_query_parameters_are_unchanged():
    client = _client()
    translate_finding({'description': 'https://example.invalid/?page=2&amp;sort=asc'}, client)
    prompt = client.messages.create.call_args.kwargs['messages'][0]['content']
    assert 'page=2&amp;sort=asc' in prompt
    assert '[REDACTED]' not in prompt
