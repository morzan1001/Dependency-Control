"""Tests for app.services.recommendation.iac."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.iac import process_iac


def _iac(
    severity="HIGH",
    component="Dockerfile",
    platform="docker",
    query_name="Healthcheck Missing",
    finding_id="iac1",
):
    return {
        "type": "iac",
        "severity": severity,
        "component": component,
        "details": {"platform": platform, "query_name": query_name},
        "id": finding_id,
    }


class TestProcessIacEmpty:
    """Edge case: no findings."""

    def test_empty_list_returns_empty(self):
        assert process_iac([]) == []

    def test_empty_iterable(self):
        assert process_iac(list()) == []


class TestProcessIacDocker:
    """Docker platform normalization."""

    def test_docker_platform_normalized(self):
        rec = process_iac([_iac(platform="docker")])[0]
        assert "Docker" in rec.title

    def test_dockerfile_platform_normalized(self):
        rec = process_iac([_iac(platform="Dockerfile")])[0]
        assert "Docker" in rec.title

    def test_type_is_fix_infrastructure(self):
        rec = process_iac([_iac()])[0]
        assert rec.type == RecommendationType.FIX_INFRASTRUCTURE

    def test_action_platform_set(self):
        rec = process_iac([_iac(platform="docker")])[0]
        assert rec.action["platform"] == "Docker"


class TestProcessIacKubernetes:
    """Kubernetes platform normalization."""

    def test_kubernetes_keyword(self):
        rec = process_iac([_iac(platform="kubernetes")])[0]
        assert "Kubernetes" in rec.title

    def test_k8s_keyword(self):
        rec = process_iac([_iac(platform="k8s")])[0]
        assert "Kubernetes" in rec.title


class TestProcessIacTerraform:
    """Terraform platform normalization."""

    def test_terraform_keyword(self):
        rec = process_iac([_iac(platform="terraform")])[0]
        assert "Terraform" in rec.title

    def test_terraform_mixed_case(self):
        rec = process_iac([_iac(platform="Terraform")])[0]
        assert "Terraform" in rec.title


class TestProcessIacAWSCloudFormation:
    """AWS/CloudFormation platform normalization."""

    def test_aws_keyword(self):
        rec = process_iac([_iac(platform="aws")])[0]
        assert "AWS/CloudFormation" in rec.title

    def test_cloudformation_keyword(self):
        rec = process_iac([_iac(platform="cloudformation")])[0]
        assert "AWS/CloudFormation" in rec.title


class TestProcessIacAnsible:
    """Ansible platform normalization."""

    def test_ansible_keyword(self):
        rec = process_iac([_iac(platform="ansible")])[0]
        assert "Ansible" in rec.title


class TestProcessIacHelm:
    """Helm platform normalization."""

    def test_helm_keyword(self):
        rec = process_iac([_iac(platform="helm")])[0]
        assert "Helm" in rec.title


class TestProcessIacBelowThreshold:
    """Findings that do not meet significance threshold are skipped."""

    def test_single_low_no_recommendation(self):
        result = process_iac([_iac(severity="LOW")])
        assert result == []

    def test_two_low_no_recommendation(self):
        findings = [
            _iac(severity="LOW", finding_id="i1"),
            _iac(severity="LOW", finding_id="i2"),
        ]
        result = process_iac(findings)
        assert result == []

    def test_single_medium_no_recommendation(self):
        result = process_iac([_iac(severity="MEDIUM")])
        assert result == []

    def test_two_medium_no_recommendation(self):
        findings = [
            _iac(severity="MEDIUM", finding_id="i1"),
            _iac(severity="MEDIUM", finding_id="i2"),
        ]
        result = process_iac(findings)
        assert result == []


class TestProcessIacAboveThreshold:
    """Findings that DO pass the threshold."""

    def test_single_high_generates_recommendation(self):
        result = process_iac([_iac(severity="HIGH")])
        assert len(result) == 1

    def test_single_critical_generates_recommendation(self):
        result = process_iac([_iac(severity="CRITICAL")])
        assert len(result) == 1

    def test_three_low_generates_recommendation(self):
        findings = [
            _iac(severity="LOW", finding_id=f"i{i}") for i in range(3)
        ]
        result = process_iac(findings)
        assert len(result) == 1


class TestProcessIacPriority:
    """Priority determination."""

    def test_critical_severity_gives_critical_priority(self):
        rec = process_iac([_iac(severity="CRITICAL")])[0]
        assert rec.priority == Priority.CRITICAL

    def test_high_severity_gives_high_priority(self):
        rec = process_iac([_iac(severity="HIGH")])[0]
        assert rec.priority == Priority.HIGH

    def test_three_medium_gives_medium_priority(self):
        findings = [
            _iac(severity="MEDIUM", finding_id=f"i{i}") for i in range(3)
        ]
        rec = process_iac(findings)[0]
        assert rec.priority == Priority.MEDIUM

    def test_three_low_gives_low_priority(self):
        findings = [
            _iac(severity="LOW", finding_id=f"i{i}") for i in range(3)
        ]
        rec = process_iac(findings)[0]
        assert rec.priority == Priority.LOW


class TestProcessIacCommonIssues:
    """Common issues extraction from query_name."""

    def test_common_issues_in_action(self):
        rec = process_iac([_iac(query_name="Healthcheck Missing")])[0]
        assert "Healthcheck Missing" in rec.action["common_issues"]

    def test_multiple_issues_sorted_by_frequency(self):
        findings = [
            _iac(query_name="Healthcheck Missing", finding_id="i1"),
            _iac(query_name="Healthcheck Missing", finding_id="i2"),
            _iac(query_name="Run As Root", finding_id="i3"),
        ]
        rec = process_iac(findings)[0]
        issues = rec.action["common_issues"]
        # Healthcheck Missing appears 2x, should come first
        assert issues[0] == "Healthcheck Missing"
        assert "Run As Root" in issues

    def test_common_issues_limited_to_five(self):
        findings = [
            _iac(query_name=f"Issue{i}", finding_id=f"i{i}", severity="HIGH")
            for i in range(8)
        ]
        rec = process_iac(findings)[0]
        assert len(rec.action["common_issues"]) <= 5


class TestProcessIacImpact:
    """Impact dict verification."""

    def test_severity_counts(self):
        findings = [
            _iac(severity="CRITICAL", finding_id="i1"),
            _iac(severity="HIGH", finding_id="i2"),
            _iac(severity="HIGH", finding_id="i3"),
        ]
        rec = process_iac(findings)[0]
        assert rec.impact["critical"] == 1
        assert rec.impact["high"] == 2
        assert rec.impact["total"] == 3

    def test_description_mentions_counts(self):
        findings = [
            _iac(severity="CRITICAL", finding_id="i1"),
            _iac(severity="HIGH", finding_id="i2"),
        ]
        rec = process_iac(findings)[0]
        assert "1 critical" in rec.description
        assert "1 high" in rec.description


class TestProcessIacMultiplePlatforms:
    """Different platforms produce separate recommendations."""

    def test_two_platforms_produce_two_recommendations(self):
        findings = [
            _iac(platform="docker", finding_id="i1"),
            _iac(platform="kubernetes", finding_id="i2"),
        ]
        result = process_iac(findings)
        assert len(result) == 2

    def test_separate_platform_titles(self):
        findings = [
            _iac(platform="docker", finding_id="i1"),
            _iac(platform="terraform", finding_id="i2"),
        ]
        result = process_iac(findings)
        titles = {r.title for r in result}
        assert "Fix Docker Misconfigurations" in titles
        assert "Fix Terraform Misconfigurations" in titles


class TestProcessIacEffort:
    """Effort is always 'medium' for IAC recommendations."""

    def test_effort_is_medium(self):
        rec = process_iac([_iac()])[0]
        assert rec.effort == "medium"


class TestProcessIacPlatformFallback:
    """Platform extraction fallbacks."""

    def test_platform_from_query_name_dot_prefix(self):
        """If platform is missing, first segment of query_name (before dot) is used."""
        finding = {
            "type": "iac",
            "severity": "HIGH",
            "component": "main.tf",
            "details": {"query_name": "terraform.something"},
            "id": "iac1",
        }
        rec = process_iac([finding])[0]
        assert "Terraform" in rec.title

    def test_fallback_to_infrastructure(self):
        """If no platform and no query_name, defaults to 'infrastructure'."""
        finding = {
            "type": "iac",
            "severity": "HIGH",
            "component": "unknown.yaml",
            "details": {},
            "id": "iac1",
        }
        rec = process_iac([finding])[0]
        assert "infrastructure" in rec.title

    def test_affected_components_limited(self):
        findings = [
            _iac(component=f"file{i}.yaml", finding_id=f"i{i}", severity="HIGH")
            for i in range(25)
        ]
        rec = process_iac(findings)[0]
        assert len(rec.affected_components) <= 20
