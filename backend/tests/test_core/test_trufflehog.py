"""The deployed trufflehog reports a numeric DetectorType; prod carries the ordinal on
31,151 of 31,151 secret findings, so it must resolve to a name for display."""

import pytest

from app.core.trufflehog import DETECTOR_TYPE_NAMES, resolve_detector_name


@pytest.mark.parametrize(
    ("ordinal", "name"),
    [
        # Every distinct details.detector value present in production.
        ("17", "URI"),
        ("9", "Gitlab"),
        ("1039", "JWT"),
        ("767", "SonarCloud"),
        ("15", "PrivateKey"),
        ("1046", "JiraDataCenterPAT"),
        ("1002", "Box"),
        ("761", "Qase"),
        ("586", "TLy"),
        ("490", "Lob"),
        ("939", "IPInfo"),
    ],
)
def test_production_ordinals_resolve_to_their_detector_name(ordinal, name):
    assert resolve_detector_name(ordinal) == name


def test_ordinal_zero_resolves_rather_than_reading_as_falsy():
    assert resolve_detector_name("0") == "Alibaba"


@pytest.mark.parametrize("raw", ["AWS", "", None, "12a", True, 9.0])
def test_non_ordinals_do_not_resolve(raw):
    assert resolve_detector_name(raw) is None


def test_unassigned_ordinal_does_not_resolve():
    """24/28/132/400 are reserved gaps in the proto; a future ordinal behaves the same."""
    assert resolve_detector_name("24") is None
    assert resolve_detector_name("999999") is None


def test_table_covers_the_whole_enum_without_duplicate_names():
    assert len(DETECTOR_TYPE_NAMES) == 1060
    assert len(set(DETECTOR_TYPE_NAMES.values())) == 1060
