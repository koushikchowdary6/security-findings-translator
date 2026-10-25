# Security Findings Translator 🔐→🗣️

[![CI](https://github.com/koushikchowdary6/security-findings-translator/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/security-findings-translator/actions/workflows/ci.yml)

Turns a technical security finding — the structured JSON output of tools like
[iam-policy-auditor](https://github.com/koushikchowdary6/iam-policy-auditor) or
[ssh-log-threat-detector](https://github.com/koushikchowdary6/ssh-log-threat-detector)
— into a plain-English explanation and **one concrete next action**, for a
reader who has never heard of IAM, brute force, or privilege escalation: a
nonprofit executive director, office manager, or board member.

It uses the **Claude API** for the translation, with a deterministic **offline
mode** so the whole pipeline runs (and is testable in CI) without an API key.

## Why

A detection tool is only useful if the person who has to act on the finding
can understand it. This is the translation layer: the same JSON your security
tools already emit, explained the way you'd explain it to a smart person
outside the field — no jargon, no alarmism, one clear step.

## Usage

**With Claude (best quality):**
```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your-key-here
python src/translator.py examples/sample_findings.json
```

**Offline (no key, no cost — template-based):**
```bash
python src/translator.py examples/sample_findings.json --offline
```

Example offline output:
```
[HIGH] iam-001
This is important to address soon. This account has a permission that lets it
hand itself even more power -- like a spare office key that can also cut new
keys for any door. If someone broke into this account, they could unlock
almost everything. Next step: ask whoever manages your cloud accounts to
review who can change access permissions, and remove this one from anyone who
doesn't clearly need it.

[CRITICAL] ssh-002
This is urgent. Someone tried many passwords in a row for one of your accounts
and eventually got in -- meaning the password was weak enough to guess, and an
intruder may be inside right now. Next step: reset that account's password
immediately and ask your IT support to check what the account did after it was
accessed.
```

(When run with a real key, Claude generates the explanations instead of the
templates — the templates exist so the tool is runnable and demonstrable by
anyone.)

## How it connects to my other work

This sits directly on top of two tools in my portfolio: it consumes the exact
finding JSON that `iam-policy-auditor` and `ssh-log-threat-detector` produce.
It's the "explain a technical thing to a non-technical room" layer for a
detection stack.

## LLM trust boundary

Before calling Claude, the translator recursively redacts recognized credential
fields (including nested passwords, tokens, and authorization values), and
recognizable inline secrets in free-text fields: common AWS/OpenAI/Anthropic/
GitHub token formats, JWTs, PEM private-key blocks, credential assignments,
and signed webhook/API URL query parameters (including `sig` and `token`).
URL sanitization preserves non-secret parameters so responders can still
recognize the affected endpoint.
This sanitizes the **API request**, without modifying local source evidence.
Offline tests use a mocked API to verify that synthetic secrets never appear in
the outbound prompt. The system prompt treats findings as untrusted evidence,
not instructions. To keep the `<finding_json>` data boundary unambiguous,
angle brackets inside JSON keys and values are serialized as JSON Unicode
escapes before the request is sent; decoded evidence remains unchanged. This
reduces delimiter-spoofing opportunities but does not guarantee resistance
to prompt injection. The Claude path also rejects token-truncated, tool-handoff,
and empty responses rather than presenting an incomplete remediation summary
as a completed translation; callers must handle these errors explicitly.

This is **defense in depth**, not a complete DLP system or proof of
prompt-injection resistance. Arbitrary, short, unusual, or encoded secrets may
still pass through. Review telemetry before sending it to an external model.

## Tests

```bash
PYTHONPATH=src python -m pytest tests/ -v
```

The tests: the Claude path is mocked (so tests run offline and cost nothing) and
checks that findings are passed to the model correctly, the system prompt is
set, and missing fields are handled; the offline template backend is tested
directly for plain language, a concrete next step, and severity-aware urgency.

## Honesty about scope

This is a working **prototype**, not a deployed product. It has **not** been
used with a real organization or validated on a real non-technical reader yet,
and the prompt/templates are tuned by inspection rather than by measuring
comprehension with an actual audience. The obvious next step is exactly that:
sit a non-technical person down with real output and see what's still
confusing. Nothing here claims a real nonprofit deployment — because there
hasn't been one.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) · [GitHub](https://github.com/koushikchowdary6)
