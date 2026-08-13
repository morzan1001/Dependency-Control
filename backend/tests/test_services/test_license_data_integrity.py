"""Enrichment must not corrupt license data: deps.dev sentinels and composite SPDX expressions."""

import pytest

from app.services.aggregation import ResultAggregator
from app.services.analyzers.license_compliance import LicenseAnalyzer

TZDATA_EXPRESSION = "LicenseRef-Fedora-Public-Domain AND (GPL-2.0-only WITH ClassPath-exception-2.0)"


class TestDepsDevSentinelRejection:
    def setup_method(self):
        self.agg = ResultAggregator()

    def _payload(self, name="aopalliance", version="1.0"):
        return self.agg.get_dependency_enrichments()[f"{name}@{version}"]

    def test_non_standard_sentinel_is_dropped(self):
        self.agg.enrich_from_deps_dev("aopalliance", "1.0", {"licenses": ["non-standard"]})
        payload = self._payload()
        assert "license" not in payload
        assert "licenses_detailed" not in payload

    def test_unknown_and_noassertion_are_dropped(self):
        self.agg.enrich_from_deps_dev("aopalliance", "1.0", {"licenses": ["unknown", "NOASSERTION"]})
        assert "license" not in self._payload()

    def test_valid_spdx_id_is_kept(self):
        self.agg.enrich_from_deps_dev("aopalliance", "1.0", {"licenses": ["Apache-2.0"]})
        payload = self._payload()
        assert payload["license"] == "Apache-2.0"
        assert payload["licenses_detailed"] == [{"spdx_id": "Apache-2.0", "source": "deps_dev"}]

    def test_id_is_normalized_before_storage(self):
        self.agg.enrich_from_deps_dev("aopalliance", "1.0", {"licenses": ["apache-2.0"]})
        assert self._payload()["license"] == "Apache-2.0"

    def test_project_block_sentinel_is_dropped(self):
        self.agg.enrich_from_deps_dev("aopalliance", "1.0", {"project": {"license": "non-standard"}})
        assert "license" not in self._payload()

    def test_project_block_valid_license_is_kept(self):
        self.agg.enrich_from_deps_dev("aopalliance", "1.0", {"project": {"license": "MIT"}})
        assert self._payload()["license"] == "MIT"


class TestCompositeExpressionOnIssues:
    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    @staticmethod
    def _component(name, version, license_str):
        return {
            "name": name,
            "version": version,
            "purl": f"pkg:rpm/redhat/{name}@{version}",
            "license": license_str,
            "scope": "runtime",
            "direct": True,
            "properties": {},
        }

    async def _issues_for(self, license_str):
        result = await self.analyzer.analyze(
            sbom={},
            settings={},
            parsed_components=[self._component("libzstd", "1.5.5-9.el10", license_str)],
        )
        return result["license_issues"]

    @pytest.mark.asyncio
    async def test_and_expression_carried_on_issue(self):
        issues = await self._issues_for("BSD-3-Clause AND GPL-2.0-only")
        assert issues
        assert all(i["spdx_expression"] == "BSD-3-Clause AND GPL-2.0-only" for i in issues)

    @pytest.mark.asyncio
    async def test_with_exception_expression_carried_on_issue(self):
        issues = await self._issues_for(TZDATA_EXPRESSION)
        assert any(i["license"] == "GPL-2.0-only" and i["spdx_expression"] == TZDATA_EXPRESSION for i in issues)

    @pytest.mark.asyncio
    async def test_comma_list_carried_on_issue(self):
        issues = await self._issues_for("Apache-2.0, GPL-2.0-only")
        assert any(
            i["license"] == "GPL-2.0-only" and i["spdx_expression"] == "Apache-2.0, GPL-2.0-only" for i in issues
        )

    @pytest.mark.asyncio
    async def test_single_license_issue_has_no_expression(self):
        issues = await self._issues_for("GPL-2.0-only")
        assert issues
        assert all("spdx_expression" not in i for i in issues)


class TestExpressionFlowsToEnrichment:
    def setup_method(self):
        self.agg = ResultAggregator()
        self.item = {
            "component": "tzdata",
            "version": "2026c-1.el10_2",
            "license": "GPL-2.0-only",
            "license_url": None,
            "severity": "HIGH",
            "category": "strong_copyleft",
            "message": "Strong copyleft license: GNU GPL v2.0 only",
            "explanation": "GPL",
            "recommendation": "Review",
            "obligations": [],
            "risks": [],
            "purl": "pkg:rpm/redhat/tzdata@2026c-1.el10_2",
            "spdx_expression": TZDATA_EXPRESSION,
        }

    def test_finding_details_carry_spdx_expression(self):
        self.agg.aggregate("license_compliance", {"license_issues": [self.item]})
        finding = next(iter(self.agg.findings.values()))
        assert finding.details["spdx_expression"] == TZDATA_EXPRESSION

    def test_enrichment_payload_carries_license_expression(self):
        self.agg.aggregate("license_compliance", {"license_issues": [self.item]})
        payload = self.agg.get_dependency_enrichments()["tzdata@2026c-1.el10_2"]
        assert payload["license"] == "GPL-2.0-only"
        assert payload["license_expression"] == TZDATA_EXPRESSION
