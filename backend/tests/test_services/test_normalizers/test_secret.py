"""Tests for secret normalizer (TruffleHog)."""

import hashlib

from app.services.aggregation import ResultAggregator


class TestNormalizeTrufflehog:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_secret(self):
        result = {
            "findings": [
                {
                    "DetectorType": "AWS",
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "secret"
        assert f.severity == "CRITICAL"
        assert f.component == "config/aws.env"
        assert "trufflehog" in f.scanners
        assert "AWS" in f.description

    def test_file_path_from_git_source(self):
        """When no Filesystem source, fall back to Git source."""
        result = {
            "findings": [
                {
                    "DetectorType": "GitHub Token",
                    "Raw": "ghp_test12345",
                    "SourceMetadata": {"Data": {"Git": {"file": "src/auth.py"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.component == "src/auth.py"

    def test_unknown_file_path_when_no_source(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.component == "unknown"

    def test_finding_id_contains_secret_hash(self):
        """Finding ID should include truncated MD5 hash of the raw secret."""
        raw_secret = "my-secret-value"
        expected_hash = hashlib.md5(raw_secret.encode()).hexdigest()[:8]
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": raw_secret,
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert expected_hash in f.id

    def test_verified_status_in_details(self):
        result = {
            "findings": [
                {
                    "DetectorType": "AWS",
                    "Verified": True,
                    "Raw": "test",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["verified"] is True

    def test_detector_in_details(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Slack Token",
                    "Raw": "xoxb-test",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["detector"] == "Slack Token"

    def test_empty_findings(self):
        self.agg.aggregate("trufflehog", {"findings": []})
        assert len(self.agg.findings) == 0

    def test_multiple_secrets(self):
        result = {
            "findings": [
                {
                    "DetectorType": "AWS",
                    "Raw": "secret1",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                },
                {
                    "DetectorType": "GitHub",
                    "Raw": "secret2",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "b.env"}}},
                },
            ]
        }
        self.agg.aggregate("trufflehog", result)
        assert len(self.agg.findings) == 2

    def test_prefers_detector_name_over_numeric_detector_type(self):
        """Prefer DetectorName over numeric DetectorType so the credential type stays recoverable."""
        result = {
            "findings": [
                {
                    "DetectorName": "AWS",
                    "DetectorType": "2",
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["detector"] == "AWS"
        assert "AWS" in f.description
        assert "AWS" in f.id
        # The numeric ordinal must not leak into user-visible fields.
        assert f.description == "Secret detected: AWS"

    def test_empty_raw_uses_nohash(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": "",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert "nohash" in f.id

    def test_git_commit_metadata_in_details(self):
        result = {
            "findings": [
                {
                    "DetectorType": "AWS",
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                    "SourceMetadata": {
                        "Data": {
                            "Git": {
                                "file": "config/aws.env",
                                "commit": "abc123def456",
                                "line": 7,
                                "timestamp": "2026-01-05T10:00:00Z",
                            }
                        }
                    },
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["commit"] == "abc123def456"
        assert f.details["line"] == 7
        assert f.details["commit_timestamp"] == "2026-01-05T10:00:00Z"

    def test_missing_git_metadata_is_none(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["commit"] is None
        assert f.details["line"] is None
        assert f.details["commit_timestamp"] is None

    def test_in_current_tree_true_from_pipeline_flag(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": True,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["in_current_tree"] is True

    def test_in_current_tree_false_from_pipeline_flag(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": False,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["in_current_tree"] is False

    def test_in_current_tree_unknown_when_flag_absent(self):
        result = {
            "findings": [
                {
                    "DetectorType": "Generic",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["in_current_tree"] is None
