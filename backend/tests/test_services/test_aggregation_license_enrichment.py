"""Primary-license selection and enrichment hygiene in the aggregator.

Entry dicts mirror the analyzer's `component_licenses` shape (prod example: glibc
carries LGPL-2.1-or-later and GPL-3.0-or-later, whose stored primary used to flip
with iteration order).
"""

from app.services.aggregation import ResultAggregator


def _entry(license_id, category, *, name="glibc", version="2.41-12", risks=None, obligations=None, expression=None):
    entry = {
        "component": name,
        "version": version,
        "purl": f"pkg:deb/debian/{name}@{version}",
        "license": license_id,
        "category": category,
        "obligations": obligations or [],
        "risks": risks or [],
        "explanation": f"{license_id} license",
    }
    if expression:
        entry["spdx_expression"] = expression
    return entry


LGPL = _entry("LGPL-2.1-or-later", "weak_copyleft", risks=["Modifications must be shared"])
GPL = _entry("GPL-3.0-or-later", "strong_copyleft", risks=["Viral copyleft"])


class TestDeterministicPrimaryLicense:
    def setup_method(self):
        self.agg = ResultAggregator()

    def _payload(self, name="glibc", version="2.41-12"):
        return self.agg.get_dependency_enrichments()[f"{name}@{version}"]

    def test_most_restrictive_wins_regardless_of_order(self):
        for first, second in ((LGPL, GPL), (GPL, LGPL)):
            agg = ResultAggregator()
            agg.aggregate("license_compliance", {"component_licenses": [first, second]})
            payload = agg.get_dependency_enrichments()["glibc@2.41-12"]
            assert payload["license"] == "GPL-3.0-or-later"
            assert payload["license_category"] == "strong_copyleft"

    def test_equal_rank_keeps_first_seen(self):
        a = _entry("GPL-2.0-only", "strong_copyleft")
        b = _entry("GPL-3.0-or-later", "strong_copyleft")
        self.agg.aggregate("license_compliance", {"component_licenses": [a, b]})
        assert self._payload()["license"] == "GPL-2.0-only"

    def test_all_licenses_recorded_in_detailed_list(self):
        self.agg.aggregate("license_compliance", {"component_licenses": [LGPL, GPL]})
        detailed = self._payload()["licenses_detailed"]
        assert {e["spdx_id"] for e in detailed} == {"LGPL-2.1-or-later", "GPL-3.0-or-later"}

    def test_risks_and_obligations_accumulate_across_licenses(self):
        self.agg.aggregate("license_compliance", {"component_licenses": [LGPL, GPL]})
        payload = self._payload()
        assert payload["license_risks"] == ["Modifications must be shared", "Viral copyleft"]

    def test_scanner_classification_replaces_deps_dev_guess(self):
        self.agg.enrich_from_deps_dev("glibc", "2.41-12", {"licenses": ["MIT"]})
        self.agg.aggregate("license_compliance", {"component_licenses": [LGPL]})
        payload = self._payload()
        assert payload["license"] == "LGPL-2.1-or-later"
        assert payload["license_category"] == "weak_copyleft"

    def test_deps_dev_does_not_replace_scanner_classification(self):
        self.agg.aggregate("license_compliance", {"component_licenses": [GPL]})
        self.agg.enrich_from_deps_dev("glibc", "2.41-12", {"licenses": ["MIT"]})
        assert self._payload()["license"] == "GPL-3.0-or-later"


class TestEnrichmentDeduplication:
    def setup_method(self):
        self.agg = ResultAggregator()

    def test_same_entry_from_two_sboms_is_recorded_once(self):
        # Multi-SBOM scans aggregate the analyzer result once per SBOM source.
        self.agg.aggregate("license_compliance", {"component_licenses": [GPL]}, source="SBOM #1")
        self.agg.aggregate("license_compliance", {"component_licenses": [GPL]}, source="SBOM #2")
        payload = self.agg.get_dependency_enrichments()["glibc@2.41-12"]
        assert len(payload["licenses_detailed"]) == 1
        assert payload["license_risks"] == ["Viral copyleft"]


class TestNoPhantomEnrichment:
    def test_compatibility_issue_creates_no_enrichment(self):
        # check_pair_conflict synthesises component "a + b" / version "va / vb" issues.
        agg = ResultAggregator()
        agg.aggregate(
            "license_compliance",
            {
                "license_issues": [
                    {
                        "component": "gpl-tool + apache-lib",
                        "version": "1.0 / 2.0",
                        "license": "GPL-2.0-only / Apache-2.0",
                        "severity": "HIGH",
                        "category": "license_incompatibility",
                        "message": "License conflict: GPL-2.0-only and Apache-2.0",
                        "purl": "pkg:npm/gpl-tool@1.0",
                    }
                ],
                "component_licenses": [],
            },
        )
        assert agg.get_dependency_enrichments() == {}
        assert len(agg.get_findings()) == 1


class TestPermissiveEnrichment:
    def test_permissive_classification_reaches_enrichment_payload(self):
        agg = ResultAggregator()
        entry = _entry("MIT", "permissive", name="lodash", version="4.17.21", obligations=["Include license text"])
        agg.aggregate("license_compliance", {"component_licenses": [entry], "license_issues": []})
        payload = agg.get_dependency_enrichments()["lodash@4.17.21"]
        assert payload["license"] == "MIT"
        assert payload["license_category"] == "permissive"
        assert payload["license_obligations"] == ["Include license text"]
        assert payload["enrichment_sources"] == ["license_compliance"]
