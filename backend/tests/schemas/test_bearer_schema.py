import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.bearer import BearerFinding, BearerIngest

_PIPELINE = {"pipeline_id": 1, "commit_hash": "a" * 40, "branch": "main"}
_BEARER_OUTPUT = json.loads((Path(__file__).parents[1] / "fixtures/sast/bearer_2.1.1_findings.json").read_text())


def test_a_real_bearer_report_is_accepted_and_kept_verbatim():
    ingest = BearerIngest.model_validate({**_PIPELINE, "findings": _BEARER_OUTPUT})

    assert ingest.findings == _BEARER_OUTPUT


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param({"title": "t", "full_filename": "a.py"}, id="without-a-rule-id"),
        pytest.param({"id": "r", "severity": 3, "full_filename": "a.py"}, id="unreadable"),
    ],
)
def test_one_entry_never_refuses_the_whole_report(entry):
    """The normalizer skips an unreadable entry and reports it, so the report is stored with its readable entries."""
    findings = {"high": [entry, *_BEARER_OUTPUT["high"]]}

    assert BearerIngest.model_validate({**_PIPELINE, "findings": findings}).findings == findings


def test_an_entry_naming_no_bearer_key_is_not_a_bearer_entry():
    with pytest.raises(ValidationError, match="no Bearer finding key"):
        BearerFinding.model_validate({"severity": "high", "detector": "AWS", "raw": "AKIAIOSFODNN7EXAMPLE"})
