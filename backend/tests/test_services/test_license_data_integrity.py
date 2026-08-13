"""Enrichment must not corrupt license data: deps.dev sentinels and composite SPDX expressions."""

import pytest

from app.services.aggregation import ResultAggregator
from app.services.analyzers.license_compliance import LicenseAnalyzer
from tests.helpers.enrichment import enrichment_payload

TZDATA_EXPRESSION = "LicenseRef-Fedora-Public-Domain AND (GPL-2.0-only WITH ClassPath-exception-2.0)"


class TestDepsDevSentinelRejection:
    def setup_method(self):
        self.agg = ResultAggregator()

    def _payload(self, name="aopalliance", version="1.0"):
        return enrichment_payload(self.agg, name, version)

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

    def test_or_expression_is_kept_verbatim(self):
        self.agg.enrich_from_deps_dev("serde", "1.0.219", {"licenses": ["Apache-2.0 OR MIT"]})
        payload = self._payload("serde", "1.0.219")
        assert payload["license"] == "Apache-2.0 OR MIT"
        assert payload["licenses_detailed"] == [{"spdx_id": "Apache-2.0 OR MIT", "source": "deps_dev"}]

    def test_and_expression_is_kept_verbatim(self):
        self.agg.enrich_from_deps_dev("miniz_oxide", "0.8.0", {"licenses": ["MIT AND Zlib"]})
        assert self._payload("miniz_oxide", "0.8.0")["license"] == "MIT AND Zlib"

    def test_with_exception_expression_is_kept_verbatim(self):
        expr = "Apache-2.0 OR MIT OR Apache-2.0 WITH LLVM-exception"
        self.agg.enrich_from_deps_dev("wasi", "0.11.0", {"licenses": [expr]})
        assert self._payload("wasi", "0.11.0")["license"] == expr

    def test_license_ref_id_is_kept(self):
        self.agg.enrich_from_deps_dev("tzdata", "2026c", {"licenses": ["LicenseRef-Fedora-Public-Domain"]})
        assert self._payload("tzdata", "2026c")["license"] == "LicenseRef-Fedora-Public-Domain"

    def test_unlisted_but_plausible_spdx_id_is_kept(self):
        self.agg.enrich_from_deps_dev("elasticsearch", "8.14.0", {"licenses": ["Elastic-2.0"]})
        assert self._payload("elasticsearch", "8.14.0")["license"] == "Elastic-2.0"

    def test_unlisted_mit_zero_is_kept(self):
        self.agg.enrich_from_deps_dev("tslib", "2.6.0", {"licenses": ["MIT-0"]})
        assert self._payload("tslib", "2.6.0")["license"] == "MIT-0"

    def test_free_text_license_is_dropped(self):
        self.agg.enrich_from_deps_dev("weird", "1.0", {"licenses": ["SEE LICENSE IN LICENSE.txt"]})
        assert "license" not in self._payload("weird", "1.0")


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
        classification = {
            "component": "tzdata",
            "version": "2026c-1.el10_2",
            "purl": "pkg:rpm/redhat/tzdata@2026c-1.el10_2",
            "license": "GPL-2.0-only",
            "category": "strong_copyleft",
            "obligations": [],
            "risks": [],
            "explanation": "GPL",
            "spdx_expression": TZDATA_EXPRESSION,
        }
        self.agg.aggregate("license_compliance", {"component_licenses": [classification]})
        payload = enrichment_payload(self.agg, "tzdata", "2026c-1.el10_2")
        assert payload["license"] == "GPL-2.0-only"
        assert payload["license_expression"] == TZDATA_EXPRESSION
