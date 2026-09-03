from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.project import Scan
from app.schemas.ingest import SBOMIngest


def _minimal_payload(**extra):
    return {"pipeline_id": 1, "commit_hash": "a" * 40, "branch": "main", **extra}


def test_existing_payload_still_validates_and_defaults_to_no_release():
    data = SBOMIngest(**_minimal_payload())
    assert data.is_release is False
    assert data.release_version is None
    assert data.release_environment is None


def test_release_payload_keeps_its_values():
    data = SBOMIngest(**_minimal_payload(is_release=True, release_version="v1.2.3", release_environment="staging"))
    assert data.is_release is True
    assert data.release_version == "v1.2.3"
    assert data.release_environment == "staging"


@pytest.mark.parametrize("bad", ["Production", "prod.eu", "-prod", "", "x" * 33])
def test_environment_slug_is_enforced_on_ingest(bad):
    with pytest.raises(ValidationError):
        SBOMIngest(**_minimal_payload(release_environment=bad))


def test_environment_slug_is_enforced_on_the_scan_model():
    with pytest.raises(ValidationError):
        Scan(project_id="p1", branch="main", release_environment="prod.eu")


def test_scan_defaults_carry_no_release():
    dumped = Scan(project_id="p1", branch="main").model_dump()
    assert dumped["is_release"] is False
    assert dumped["release_version"] is None
    assert dumped["release_environment"] is None
    assert dumped["released_at"] is None


def test_release_fields_are_empty_when_not_a_release():
    data = SBOMIngest(**_minimal_payload(commit_tag="v9"))
    assert data.release_fields(datetime.now(timezone.utc)) == {}


def test_release_fields_fall_back_to_commit_tag_and_production():
    now = datetime.now(timezone.utc)
    data = SBOMIngest(**_minimal_payload(commit_tag="v9", is_release=True))
    assert data.release_fields(now) == {
        "is_release": True,
        "release_version": "v9",
        "release_environment": "production",
        "released_at": now,
    }
