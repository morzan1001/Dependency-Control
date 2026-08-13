"""The analyzer classifies every recognised component license, not just policy violations."""

import pytest

from app.services.analyzers.license_compliance import LicenseAnalyzer


def _component(name, version, license_str, *, scope="runtime", direct=True):
    return {
        "name": name,
        "version": version,
        "purl": f"pkg:npm/{name}@{version}",
        "license": license_str,
        "scope": scope,
        "direct": direct,
        "properties": {},
    }


async def _analyze(components, settings=None):
    return await LicenseAnalyzer().analyze(sbom={}, settings=settings or {}, parsed_components=components)


@pytest.mark.asyncio
async def test_permissive_component_is_classified_without_a_finding():
    result = await _analyze([_component("lodash", "4.17.21", "MIT")])

    assert result["license_issues"] == []
    assert result["component_licenses"] == [
        {
            "component": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "license": "MIT",
            "category": "permissive",
            "obligations": result["component_licenses"][0]["obligations"],
            "risks": result["component_licenses"][0]["risks"],
            "explanation": result["component_licenses"][0]["explanation"],
        }
    ]


@pytest.mark.asyncio
async def test_copyleft_component_yields_both_issue_and_classification():
    result = await _analyze([_component("readline", "8.2", "GPL-3.0-only")])

    assert len(result["license_issues"]) == 1
    entries = result["component_licenses"]
    assert len(entries) == 1
    assert entries[0]["license"] == "GPL-3.0-only"
    assert entries[0]["category"] == "strong_copyleft"
    assert entries[0]["risks"]


@pytest.mark.asyncio
async def test_suppressed_transitive_finding_still_classifies():
    # Weak copyleft on a transitive dep: the INFO finding is suppressed as noise,
    # but the classification must survive for the inventory category column.
    result = await _analyze([_component("libfoo", "1.0", "LGPL-2.1-or-later", direct=False)])

    assert result["license_issues"] == []
    assert [e["category"] for e in result["component_licenses"]] == ["weak_copyleft"]


@pytest.mark.asyncio
async def test_dev_scoped_component_is_not_classified():
    result = await _analyze([_component("jest", "29.0.0", "MIT", scope="dev")])

    assert result["component_licenses"] == []
    assert result["summary"]["skipped"] == 1


@pytest.mark.asyncio
async def test_unknown_license_is_not_classified():
    result = await _analyze([_component("mystery", "1.0", "Custom-EULA-2024")])

    assert result["component_licenses"] == []
    assert result["summary"]["unknown"] == 1


@pytest.mark.asyncio
async def test_or_expression_classifies_least_restrictive_alternative():
    result = await _analyze([_component("serde", "1.0.219", "Apache-2.0 OR GPL-3.0-only")])

    entries = result["component_licenses"]
    assert [e["license"] for e in entries] == ["Apache-2.0"]
    assert entries[0]["spdx_expression"] == "Apache-2.0 OR GPL-3.0-only"


@pytest.mark.asyncio
async def test_and_expression_classifies_every_member():
    result = await _analyze([_component("libzstd", "1.5.5", "BSD-3-Clause AND GPL-2.0-only")])

    entries = result["component_licenses"]
    assert {e["license"] for e in entries} == {"BSD-3-Clause", "GPL-2.0-only"}
    assert all(e["spdx_expression"] == "BSD-3-Clause AND GPL-2.0-only" for e in entries)


@pytest.mark.asyncio
async def test_compatibility_conflicts_do_not_appear_in_component_licenses():
    result = await _analyze(
        [
            _component("gpl2-tool", "1.0", "GPL-2.0-only"),
            _component("gpl3-lib", "2.0", "GPL-3.0-only"),
        ]
    )

    synthetic = [i for i in result["license_issues"] if " + " in i["component"]]
    assert synthetic, "expected the GPL-2.0-only/GPL-3.0-only conflict issue"
    assert all(" + " not in e["component"] for e in result["component_licenses"])
