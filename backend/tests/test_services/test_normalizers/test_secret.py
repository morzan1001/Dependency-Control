"""Tests for secret normalizer (TruffleHog)."""

import hashlib

import pytest

from app.services.aggregation import ResultAggregator

_AWS_DESCRIPTION = (
    "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand "
    "services like computing power, storage, databases. API keys for AWS can have varying amount of access to these "
    "services depending on the IAM policy attached."
)
# trufflehog 3.97.9 `filesystem` and `git` output lines; the key material is swapped for AWS's documented example key.
_FILESYSTEM_FINDING = {
    "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/config.py", "line": 3}}},
    "SourceID": 1,
    "SourceType": 15,
    "SourceName": "trufflehog - filesystem",
    "DetectorType": 2,
    "DetectorName": "AWS",
    "DetectorDescription": _AWS_DESCRIPTION,
    "DecoderName": "PLAIN",
    "Verified": False,
    "VerificationFromCache": False,
    "Raw": "AKIAIOSFODNN7EXAMPLE",
    "RawV2": "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Redacted": "AKIAIOSFODNN7EXAMPLE",
    "ExtraData": {"account": "123456789012", "resource_type": "Access key"},
    "StructuredData": None,
    "SecretParts": {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    },
}
_GIT_FINDING = {
    **_FILESYSTEM_FINDING,
    "SourceMetadata": {
        "Data": {
            "Git": {
                "commit": "a62105a16d9d66601e919bf2d2449afd3d437d2a",
                "file": "config.py",
                "email": "dev <dev@example.com>",
                "repository": "file:///repo",
                "timestamp": "2026-09-29 21:38:35 +0000",
                "line": 3,
                "repository_local_path": "/tmp/trufflehog-24-831200535",
            }
        }
    },
    "SourceType": 16,
    "SourceName": "trufflehog - git",
}


def _with_line(line, source):
    return {**_FILESYSTEM_FINDING, "SourceMetadata": {"Data": {source: {"file": "config.py", "line": line}}}}


def _only_finding(*entries):
    agg = ResultAggregator()
    agg.aggregate("trufflehog", {"findings": list(entries)})
    (finding,) = agg.findings.values()
    return finding


class TestRealTrufflehogOutput:
    def test_filesystem_finding_keeps_its_line_and_detector_name(self):
        f = _only_finding(_FILESYSTEM_FINDING)
        assert (f.component, f.description, f.id) == ("/scan/config.py", "Secret detected: AWS", "SECRET-2-317e5726")
        assert f.details["detector"] == "2"
        assert f.details["detector_name"] == "AWS"
        assert f.details["line"] == 3

    def test_git_finding_keeps_line_commit_and_timestamp(self):
        f = _only_finding(_GIT_FINDING)
        assert f.component == "config.py"
        assert (f.details["line"], f.details["commit"], f.details["commit_timestamp"]) == (
            3,
            "a62105a16d9d66601e919bf2d2449afd3d437d2a",
            "2026-09-29 21:38:35 +0000",
        )

    def test_a_detector_newer_than_this_release_is_named_by_the_scanner(self):
        f = _only_finding({**_FILESYSTEM_FINDING, "DetectorType": 1070, "DetectorName": "FutureCloudToken"})
        assert f.description == "Secret detected: FutureCloudToken"
        assert f.details["detector"] == "1070"

    def test_without_a_detector_name_the_description_names_the_ordinal(self):
        entry = {key: value for key, value in _FILESYSTEM_FINDING.items() if key != "DetectorName"}
        f = _only_finding(entry)
        assert f.description == "Secret detected: 2"
        assert "detector_name" not in f.details

    @pytest.mark.parametrize("source", ["Filesystem", "Git"])
    @pytest.mark.parametrize(("line", "stored"), [("42", 42), ("0", 0), (999_999_999, 999_999_999)])
    def test_a_line_number_is_kept(self, line, stored, source):
        assert _only_finding(_with_line(line, source)).details["line"] == stored

    @pytest.mark.parametrize("source", ["Filesystem", "Git"])
    @pytest.mark.parametrize(
        "line",
        ["²", "\uff11\uff12", "1" * 5000, 10**30, -1, True, 3.5, "12a"],
        ids=["superscript", "full-width", "5000-digits", "huge-int", "negative", "bool", "float", "suffix"],
    )
    def test_a_line_that_is_no_ascii_number_is_dropped(self, line, source):
        assert "line" not in _only_finding(_with_line(line, source)).details


class TestNormalizeTrufflehog:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_secret(self):
        result = {
            "findings": [
                {
                    "DetectorType": "2",
                    "DetectorName": "AWS",
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
        assert f.description == "Secret detected: AWS"

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
        """The ordinal, not the name, must reach finding_id and details.detector: 373 of 504
        production waivers carry `SECRET-<ordinal>-<hash>` and a `match.rule_key` of the same
        ordinal, so a name there would silently un-suppress them."""
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
        assert f.description == "Secret detected: AWS"

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
