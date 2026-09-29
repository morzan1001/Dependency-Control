import pytest

from app.schemas.sbom import UNKNOWN_VERSION, has_known_version
from app.services.sbom_parser import SBOMParser


@pytest.mark.parametrize("raw", [None, "", "  ", "unknown", "NOASSERTION", "none", {"v": 1}])
def test_placeholder_versions_normalize_to_the_unknown_marker(raw):
    version = SBOMParser._normalize_version(raw)
    assert version == UNKNOWN_VERSION
    assert not has_known_version(version)


@pytest.mark.parametrize("version", ["1.2.3", "0", "2:1.0-1"])
def test_real_versions_are_known(version):
    assert has_known_version(SBOMParser._normalize_version(version))


def test_missing_version_is_not_known():
    assert not has_known_version(None)
    assert not has_known_version("")
