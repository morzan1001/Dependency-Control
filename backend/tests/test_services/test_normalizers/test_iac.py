"""Tests for IaC normalizer (KICS)."""

from app.services.aggregator import ResultAggregator


class TestNormalizeKics:
    """Tests for normalize_kics - KICS IaC scanner normalization."""

    def setup_method(self):
        self.agg = ResultAggregator()

    def test_basic_finding(self):
        result = {
            "queries": [
                {
                    "query_name": "Container Not Limited Memory",
                    "query_id": "qid-1234",
                    "severity": "HIGH",
                    "description": "Container should have memory limits",
                    "platform": "Kubernetes",
                    "category": "Resource Management",
                    "files": [{"file_name": "deployment.yaml", "line": 25, "end_line": 30}],
                }
            ]
        }
        self.agg.aggregate("kics", result)
        findings = self.agg.get_findings()
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "iac"
        assert f.component == "deployment.yaml"
        assert f.severity == "HIGH"
        assert "kics" in f.scanners
        assert "Container Not Limited Memory" in f.description

    def test_per_file_findings(self):
        """Each file in a query should create a separate finding."""
        result = {
            "queries": [
                {
                    "query_name": "Missing Limit",
                    "query_id": "qid-1",
                    "severity": "HIGH",
                    "description": "desc",
                    "platform": "Kubernetes",
                    "category": "Resource",
                    "files": [
                        {"file_name": "deploy-a.yaml", "line": 10},
                        {"file_name": "deploy-b.yaml", "line": 20},
                    ],
                }
            ]
        }
        self.agg.aggregate("kics", result)
        assert len(self.agg.findings) == 2

    def test_severity_mapping(self):
        """KICS TRACE maps to INFO."""
        result = {
            "queries": [
                {
                    "query_name": "Minor issue",
                    "query_id": "qid-1",
                    "severity": "TRACE",
                    "description": "desc",
                    "platform": "Docker",
                    "category": "Best Practice",
                    "files": [{"file_name": "Dockerfile", "line": 1}],
                }
            ]
        }
        self.agg.aggregate("kics", result)
        f = list(self.agg.findings.values())[0]
        assert f.severity == "INFO"

    def test_actual_expected_values(self):
        result = {
            "queries": [
                {
                    "query_name": "test",
                    "query_id": "qid-1",
                    "severity": "MEDIUM",
                    "description": "desc",
                    "platform": "Kubernetes",
                    "category": "cat",
                    "files": [
                        {
                            "file_name": "deploy.yaml",
                            "line": 10,
                            "actual_value": "'runAsRoot' is true",
                            "expected_value": "'runAsRoot' should be false",
                        }
                    ],
                }
            ]
        }
        self.agg.aggregate("kics", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["actual_value"] == "'runAsRoot' is true"
        assert f.details["expected_value"] == "'runAsRoot' should be false"

    def test_empty_queries_skipped(self):
        self.agg.aggregate("kics", {"queries": []})
        assert len(self.agg.findings) == 0

    def test_no_queries_key_skipped(self):
        self.agg.aggregate("kics", {"other": "data"})
        assert len(self.agg.findings) == 0

    def test_platform_in_details(self):
        result = {
            "queries": [
                {
                    "query_name": "test",
                    "query_id": "qid-1",
                    "severity": "LOW",
                    "description": "desc",
                    "platform": "Terraform",
                    "category": "cat",
                    "files": [{"file_name": "main.tf", "line": 1}],
                }
            ]
        }
        self.agg.aggregate("kics", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["platform"] == "Terraform"

    def test_cwe_normalized(self):
        result = {
            "queries": [
                {
                    "query_name": "test",
                    "query_id": "qid-1",
                    "severity": "HIGH",
                    "description": "desc",
                    "platform": "K8s",
                    "category": "cat",
                    "cwe": ["CWE-250"],
                    "files": [{"file_name": "file.yaml", "line": 1}],
                }
            ]
        }
        self.agg.aggregate("kics", result)
        f = list(self.agg.findings.values())[0]
        assert f.details["cwe_ids"] == ["250"]
