"""Tests for Waiver model."""

from datetime import datetime, timezone

from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK
from app.models.waiver import Waiver, is_waiver_active


class TestWaiverModel:
    def test_minimal_valid_waiver(self):
        waiver = Waiver(reason="False positive", created_by="admin")
        assert waiver.reason == "False positive"
        assert waiver.created_by == "admin"

    def test_default_status(self):
        waiver = Waiver(reason="Test", created_by="admin")
        assert waiver.status == WAIVER_STATUS_ACCEPTED_RISK

    def test_project_scope(self):
        waiver = Waiver(
            project_id="proj-1",
            reason="Project-specific",
            created_by="admin",
        )
        assert waiver.project_id == "proj-1"

    def test_global_scope(self):
        waiver = Waiver(reason="Global waiver", created_by="admin")
        assert waiver.project_id is None

    def test_all_matching_criteria(self):
        waiver = Waiver(
            finding_id="CVE-2023-1234",
            package_name="requests",
            package_version="2.26.0",
            vulnerability_id="CVE-2023-1234",
            reason="Accepted risk",
            created_by="admin",
        )
        assert waiver.finding_id == "CVE-2023-1234"
        assert waiver.package_name == "requests"
        assert waiver.package_version == "2.26.0"


class TestWaiverExpiry:
    # Motor hands back tz-naive datetimes, so every expiration_date loaded from Mongo takes this path.
    _NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_naive_expiration_in_the_future_stays_active(self):
        assert is_waiver_active(datetime(2030, 1, 1), now=self._NOW) is True  # noqa: DTZ001

    def test_naive_expiration_in_the_past_is_expired(self):
        assert is_waiver_active(datetime(2020, 1, 1), now=self._NOW) is False  # noqa: DTZ001

    def test_is_active_reads_a_naive_expiration_without_raising(self):
        waiver = Waiver(reason="Test", created_by="admin", expiration_date=datetime(2030, 1, 1))  # noqa: DTZ001
        assert waiver.expiration_date.tzinfo is None
        assert waiver.is_active is True

    def test_missing_expiration_never_expires(self):
        assert is_waiver_active(None) is True
