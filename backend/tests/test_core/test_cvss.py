"""CVSS v3.x base-score computation, checked against published scores.

OSV rates with a vector and no number, so an unparsed vector is a rating discarded.
"""

import pytest

from app.core.cvss import cvss3_base_score


@pytest.mark.parametrize(
    "vector,expected",
    [
        # Real OSV records, RHSA advisories on production images.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", 8.2),  # RHSA-2022:4584 (zlib)
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),
        # CVSS v3.1 specification examples.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        # Only a scope change can reach 10.0.
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        # v3.0 vectors score identically on the base metrics.
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", 8.2),
        # No impact at all scores zero, never a rounded-up floor.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_published_scores(vector, expected):
    assert cvss3_base_score(vector) == pytest.approx(expected)


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # v4 needs a lookup table
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",  # v2, absent from production OSV records
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown metric value
        "CVSS:3.1/AV:N/AC:L",  # truncated
        "not-a-cvss-vector",
        "",
    ],
)
def test_unscoreable_vectors_return_none(vector):
    assert cvss3_base_score(vector) is None


def test_surrounding_whitespace_is_tolerated():
    assert cvss3_base_score("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H  ") == pytest.approx(8.2)


def test_a_repeated_metric_is_rejected_rather_than_silently_last_wins():
    """The two occurrences score 9.8 and 6.5; picking either would be a guess, and the
    reference implementation rejects the vector."""
    duplicated = "CVSS:3.1/AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    assert cvss3_base_score(duplicated) is None
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == pytest.approx(9.8)
    assert cvss3_base_score("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == pytest.approx(8.8)
