from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from app.models.project import Scan
from app.models.release import Release
from app.schemas.ingest import SBOMIngest

_MAX_ENVIRONMENT_LENGTH = 32
_PIPELINE_ID = 1
_COMMIT = "a" * 40
_BRANCH = "main"
_PROJECT_ID = "p1"
_SCAN_ID = "s1"
_STAGING = "staging"
_VERSION = "v1.2.3"
_COMMIT_TAG = "v9"
_SCAN_FIELDS_THAT_MOVED_TO_THE_RELEASE = ("release_version", "release_environment", "released_at")


def _minimal_payload(**extra):
    return {"pipeline_id": _PIPELINE_ID, "commit_hash": _COMMIT, "branch": _BRANCH, **extra}


def test_existing_payload_still_validates_and_defaults_to_no_release():
    data = SBOMIngest(**_minimal_payload())
    assert data.is_release is False
    assert data.release_version is None
    assert data.release_environment is None


def test_release_payload_keeps_its_values():
    data = SBOMIngest(**_minimal_payload(is_release=True, release_version=_VERSION, release_environment=_STAGING))
    assert data.is_release is True
    assert data.release_version == _VERSION
    assert data.release_environment == _STAGING


@pytest.mark.parametrize("good", ["staging", "prod_eu", "prod-eu", "1prod", "a", "z" * _MAX_ENVIRONMENT_LENGTH])
def test_environment_slug_accepts_valid_values(good):
    data = SBOMIngest(**_minimal_payload(release_environment=good))
    assert data.release_environment == good


@pytest.mark.parametrize("bad", ["Production", "prod.eu", "-prod", "", "x" * (_MAX_ENVIRONMENT_LENGTH + 1), "prod\n"])
def test_environment_slug_is_enforced_on_ingest(bad):
    with pytest.raises(ValidationError):
        SBOMIngest(**_minimal_payload(release_environment=bad))


def test_the_scan_carries_the_flag_and_nothing_else():
    dumped = Scan(project_id=_PROJECT_ID, branch=_BRANCH).model_dump()
    assert dumped["is_release"] is False
    for field in _SCAN_FIELDS_THAT_MOVED_TO_THE_RELEASE:
        assert field not in dumped


def test_ingest_schema_rejects_caller_supplied_released_at():
    now = datetime.now(timezone.utc)
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    data = SBOMIngest(**_minimal_payload(released_at=past, is_release=True))
    assert not hasattr(data, "released_at")
    assert data.release_fields(now)["released_at"] == now


def test_release_fields_are_empty_when_not_a_release():
    data = SBOMIngest(**_minimal_payload(commit_tag=_COMMIT_TAG))
    assert data.release_fields(datetime.now(timezone.utc)) == {}


def test_release_fields_fall_back_to_commit_tag_and_production():
    now = datetime.now(timezone.utc)
    data = SBOMIngest(**_minimal_payload(commit_tag=_COMMIT_TAG, is_release=True))
    assert data.release_fields(now) == {
        "environment": DEFAULT_RELEASE_ENVIRONMENT,
        "version": _COMMIT_TAG,
        "released_at": now,
    }


def test_release_fields_name_the_keys_of_a_release_document():
    """Both ingest paths splat these into Release(), so a key rename must fail here, not silently."""
    now = datetime.now(timezone.utc)
    data = SBOMIngest(**_minimal_payload(is_release=True, release_environment=_STAGING, release_version=_VERSION))
    release = Release(project_id=_PROJECT_ID, scan_id=_SCAN_ID, **data.release_fields(now))
    assert (release.project_id, release.environment, release.version, release.scan_id, release.released_at) == (
        _PROJECT_ID,
        _STAGING,
        _VERSION,
        _SCAN_ID,
        now,
    )
