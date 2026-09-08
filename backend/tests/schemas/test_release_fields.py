from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.core.constants import DEFAULT_RELEASE_ENVIRONMENT
from app.models.project import Scan
from app.models.release import Release
from app.schemas.ingest import SBOMIngest
from app.schemas.project import ScanReleaseRef
from app.schemas.release import ReleaseItem

_MAX_ENVIRONMENT_LENGTH = 32
_PIPELINE_ID = 1
_COMMIT = "a" * 40
_BRANCH = "main"
_PROJECT_ID = "p1"
_SCAN_ID = "s1"
_STAGING = "staging"
_VERSION = "v1.2.3"
_COMMIT_TAG = "v9"
_UNSET = ""
_FIELDS_A_SCAN_MUST_NOT_CARRY = ("release_version", "release_environment", "released_at")
# Mongo stores UTC and hands the value back with the zone dropped; that naivety is the input here.
_NAIVE_RELEASED_AT = datetime(2026, 9, 4, 22, 30, tzinfo=timezone.utc).replace(tzinfo=None)
_OFFSET_RELEASED_AT = datetime(2026, 9, 4, 22, 30, tzinfo=timezone(timedelta(hours=2)))
_UTC_SUFFIX = "Z"


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


def test_the_scan_carries_the_flag_and_no_deploy_target():
    dumped = Scan(project_id=_PROJECT_ID, branch=_BRANCH).model_dump()
    assert dumped["is_release"] is False
    for field in _FIELDS_A_SCAN_MUST_NOT_CARRY:
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


@pytest.mark.parametrize(
    "payload",
    [
        {"commit_tag": _UNSET},
        {"commit_tag": _UNSET, "release_version": _UNSET},
        {"release_version": _UNSET},
        {},
    ],
    ids=["blank tag", "both blank", "blank version", "neither sent"],
)
def test_a_release_off_a_branch_pipeline_is_unnamed_rather_than_named_blank(payload):
    """ReleaseRepository.record skips a None version but stores an empty one as the release's name."""
    data = SBOMIngest(**_minimal_payload(is_release=True, **payload))
    assert data.release_fields(datetime.now(timezone.utc))["version"] is None


def test_a_blank_release_version_still_falls_back_to_the_commit_tag():
    data = SBOMIngest(**_minimal_payload(is_release=True, release_version=_UNSET, commit_tag=_COMMIT_TAG))
    assert data.release_fields(datetime.now(timezone.utc))["version"] == _COMMIT_TAG


@pytest.mark.parametrize(
    "build",
    [
        lambda when: ReleaseItem(
            scan_id=_SCAN_ID, project_id=_PROJECT_ID, environment=_STAGING, released_at=when
        ).model_dump_json(),
        lambda when: ScanReleaseRef(environment=_STAGING, released_at=when).model_dump_json(),
    ],
    ids=["release listing", "scan release ref"],
)
def test_released_at_leaves_the_api_with_its_zone(build):
    """Mongo returns the timestamp naive, and a bare one invites a client to read it as local time."""
    assert _UTC_SUFFIX in build(_NAIVE_RELEASED_AT)


def test_an_offset_the_caller_supplied_survives_untouched():
    item = ReleaseItem(scan_id=_SCAN_ID, project_id=_PROJECT_ID, environment=_STAGING, released_at=_OFFSET_RELEASED_AT)
    assert item.released_at == _OFFSET_RELEASED_AT


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
