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
                    "DetectorType": "2",
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
        assert f.description == "Secret detected: 2"

    def test_file_path_from_git_source(self):
        """When no Filesystem source, fall back to Git source."""
        result = {
            "findings": [
                {
                    "DetectorType": "8",
                    "Raw": "ghp_test12345",
                    "SourceMetadata": {"Data": {"Git": {"file": "src/auth.py"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.component == "src/auth.py"

    def test_unknown_file_path_when_no_source(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.component == "unknown"

    def test_finding_id_contains_secret_hash(self):
        """Finding ID should include truncated MD5 hash of the raw secret."""
        raw_secret = "my-secret-value"
        expected_hash = hashlib.md5(raw_secret.encode()).hexdigest()[:8]
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": raw_secret,
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert expected_hash in f.id

    def test_verified_status_in_details(self):
        result = {
            "findings": [
                {
                    "DetectorType": "2",
                    "Verified": True,
                    "Raw": "test",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["verified"] is True

    def test_detector_in_details(self):
        result = {
            "findings": [
                {
                    "DetectorType": "13",
                    "Raw": "xoxb-test",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["detector"] == "13"

    def test_empty_findings(self):
        self.agg.aggregate("trufflehog", {"findings": []})
        assert len(self.agg.findings) == 0

    def test_multiple_secrets(self):
        result = {
            "findings": [
                {
                    "DetectorType": "2",
                    "Raw": "secret1",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                },
                {
                    "DetectorType": "8",
                    "Raw": "secret2",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "b.env"}}},
                },
            ]
        }
        self.agg.aggregate("trufflehog", result)
        assert len(self.agg.findings) == 2

    def test_detector_type_ordinal_is_the_stored_identity(self):
        """The ordinal, not the name, must reach finding_id: 373 of 504 production waivers
        carry `SECRET-<ordinal>-<hash>` and a `match.rule_key` of the same ordinal, and the
        ingest schema drops DetectorName, so a name here would silently un-suppress them."""
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
        f = next(iter(self.agg.findings.values()))
        assert f.details["detector"] == "2"
        assert f.id.startswith("SECRET-2-")
        assert f.description == "Secret detected: 2"

    def test_empty_raw_uses_nohash(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "",
                    "SourceMetadata": {"Data": {}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert "nohash" in f.id

    def test_git_commit_metadata_in_details(self):
        result = {
            "findings": [
                {
                    "DetectorType": "2",
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
        f = next(iter(self.agg.findings.values()))
        assert f.details["commit"] == "abc123def456"
        assert f.details["line"] == 7
        assert f.details["commit_timestamp"] == "2026-01-05T10:00:00Z"

    def test_missing_git_metadata_is_none(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        # exclude_none drops absent git metadata entirely; readers use .get().
        assert f.details.get("commit") is None
        assert f.details.get("line") is None
        assert f.details.get("commit_timestamp") is None

    def test_in_current_tree_true_from_pipeline_flag(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": True,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["in_current_tree"] is True

    def test_in_current_tree_false_from_pipeline_flag(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": False,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["in_current_tree"] is False

    def test_in_current_tree_unknown_when_flag_absent(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details.get("in_current_tree") is None

    def test_verified_secret_has_boosted_adjusted_risk_score(self):
        result = {
            "findings": [
                {
                    "DetectorType": "2",
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.env"}}},
                    "DcInCurrentTree": False,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["risk_score"] == 40.0
        assert abs(f.details["adjusted_risk_score"] - 44.0) < 0.01

    def test_unverified_historical_secret_has_deprioritized_score(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": False,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.details["adjusted_risk_score"] == 16.0

    def test_unverified_historical_secret_severity_is_low(self):
        """Unverified + gone-from-tree is the deprioritized bucket: severity drops to LOW so it
        leaves the critical counts everywhere (all aggregations key on severity)."""
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": False,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.severity == "LOW"

    def test_verified_historical_secret_stays_critical(self):
        """A verified credential is a live leak until rotated, even after the file is gone."""
        result = {
            "findings": [
                {
                    "DetectorType": "2",
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": False,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.severity == "CRITICAL"

    def test_unverified_in_current_tree_stays_critical(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                    "DcInCurrentTree": True,
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.severity == "CRITICAL"

    def test_unknown_tree_status_stays_critical(self):
        result = {
            "findings": [
                {
                    "DetectorType": "7",
                    "Raw": "secret123",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env"}}},
                }
            ]
        }
        self.agg.aggregate("trufflehog", result)
        f = next(iter(self.agg.findings.values()))
        assert f.severity == "CRITICAL"
