"""Untrusted finding JSON must have bounded structural nesting before parsing."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from translator import (  # noqa: E402
    MAX_FINDINGS_JSON_NESTING,
    translate_findings_file,
)


def _nested_finding(depth):
    # The root finding object counts as the first structural level.
    arrays = depth - 1
    return ('{"id":"case","details":' + "[" * arrays
            + '"safe"' + "]" * arrays + "}")


def test_exact_depth_boundary_remains_usable(tmp_path):
    path = tmp_path / "boundary.json"
    path.write_text(_nested_finding(MAX_FINDINGS_JSON_NESTING), encoding="utf-8")
    result = translate_findings_file(str(path), offline=True)
    assert len(result) == 1
    assert result[0].finding_id == "case"


def test_excessive_depth_rejected_before_any_paid_client(tmp_path, monkeypatch):
    path = tmp_path / "too-deep.json"
    path.write_text(_nested_finding(MAX_FINDINGS_JSON_NESTING + 1), encoding="utf-8")
    client_factory = MagicMock()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-test-key")
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=client_factory))
    with pytest.raises(ValueError, match="nesting depth limit"):
        translate_findings_file(str(path), offline=False)
    client_factory.assert_not_called()


def test_brackets_and_escaped_quotes_inside_strings_do_not_count(tmp_path):
    path = tmp_path / "quoted.json"
    finding = {"id": "quoted", "details": '[{"\\\"": "]]]{{{"}]]]', "label": "café"}
    path.write_text(json.dumps(finding, ensure_ascii=False), encoding="utf-8")
    result = translate_findings_file(str(path), offline=True)
    assert [item.finding_id for item in result] == ["quoted"]


def test_nested_batch_counts_outer_array_and_each_object(tmp_path):
    path = tmp_path / "batch.json"
    # Outer array + root object + inner arrays = the structural depth.
    allowed_arrays = MAX_FINDINGS_JSON_NESTING - 2
    path.write_text("[" + _nested_finding(allowed_arrays + 1) + "]", encoding="utf-8")
    assert len(translate_findings_file(str(path), offline=True)) == 1
    path.write_text("[" + _nested_finding(allowed_arrays + 2) + "]", encoding="utf-8")
    with pytest.raises(ValueError, match="nesting depth limit"):
        translate_findings_file(str(path), offline=True)
