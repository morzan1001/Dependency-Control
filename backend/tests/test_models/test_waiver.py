"""Tests for Waiver model."""

from app.models.waiver import Waiver
from app.core.constants import WAIVER_STATUS_ACCEPTED_RISK


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
