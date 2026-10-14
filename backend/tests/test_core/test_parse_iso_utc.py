"""parse_iso_utc reads an ISO 8601 timestamp as an aware datetime, and anything else as None."""

from datetime import datetime, timezone

import pytest

from app.core import parse_iso_utc

_NOON = datetime(2024, 5, 1, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "raw",
    ["2024-05-01T12:00:00Z", "2024-05-01T12:00:00+00:00", "2024-05-01T14:00:00+02:00", "2024-05-01T12:00:00"],
    ids=["zulu", "offset", "other-offset", "naive"],
)
def test_a_timestamp_is_read_as_an_aware_datetime(raw):
    parsed = parse_iso_utc(raw)

    assert parsed == _NOON
    assert parsed is not None and parsed.tzinfo is not None


@pytest.mark.parametrize("raw", [None, "", "yesterday", 1714564800, ["2024-05-01T12:00:00Z"]])
def test_anything_else_is_none(raw):
    assert parse_iso_utc(raw) is None
