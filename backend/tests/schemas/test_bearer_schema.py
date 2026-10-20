import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.bearer import BearerIngest

_PIPELINE = {"pipeline_id": 1, "commit_hash": "a" * 40, "branch": "main"}
_BEARER_OUTPUT = json.loads((Path(__file__).parents[1] / "fixtures/sast/bearer_2.1.1_findings.json").read_text())


def test_a_real_bearer_report_is_accepted_and_kept_verbatim():
    ingest = BearerIngest.model_validate({**_PIPELINE, "findings": _BEARER_OUTPUT})

    assert ingest.findings == _BEARER_OUTPUT


def test_an_entry_the_normalizer_cannot_read_is_rejected_before_it_is_stored():
    with pytest.raises(ValidationError, match="id"):
        BearerIngest.model_validate({**_PIPELINE, "findings": {"high": [{"title": "t", "full_filename": "a.py"}]}})
