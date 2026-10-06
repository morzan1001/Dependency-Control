"""A node that only structures an SBOM is not reported as a component the parser dropped."""

import json
from pathlib import Path

import pytest

from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.sbom_parser import parse_sbom
from tests.mocks.fake_mongo import FakeDatabase

_SBOMS = Path(__file__).parents[1] / "fixtures" / "sbom"

_ZLIB = {
    "bom-ref": "pkg:generic/zlib@1.3",
    "type": "library",
    "name": "zlib",
    "version": "1.3",
    "purl": "pkg:generic/zlib@1.3",
}


def _graph_sbom(node: dict) -> dict:
    """The node sits where Trivy puts a lock-file or binary node: between the scanned root and a package."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "/src"}},
        "components": [node, _ZLIB],
        "dependencies": [{"ref": "root", "dependsOn": ["bin"]}, {"ref": "bin", "dependsOn": [_ZLIB["bom-ref"]]}],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fixture",
    [
        "maven.trivy.cdx.json",
        "mono.trivy.cdx.json",
        "gomod.trivy.cdx.json",
        "cargo.trivy.cdx.json",
        "cargows.trivy.cdx.json",
        "gobinary.trivy.cdx.json",
        "gobinnomain.trivy.cdx.json",
        "mono.syft.spdx.json",
    ],
)
async def test_a_grouping_node_or_document_root_is_not_reported_as_dropped(fixture):
    request = AdhocAnalyzeRequest(
        sboms=[json.loads((_SBOMS / fixture).read_text())], analyzers=["license_compliance"], apply_global_waivers=False
    )

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped_inputs == {}


def test_a_cpe_identified_application_inside_the_graph_stays_a_dependency():
    node = {
        "bom-ref": "bin",
        "type": "application",
        "name": "openssl",
        "version": "3.0.2",
        "cpe": "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*",
    }

    result = parse_sbom(_graph_sbom(node))

    assert sorted(dep.name for dep in result.dependencies) == ["openssl", "zlib"]


def test_an_unhashable_bom_ref_on_a_purl_less_application_does_not_fail_the_document():
    result = parse_sbom(_graph_sbom({"bom-ref": ["bin"], "type": "application", "name": "odd"}))

    assert [dep.name for dep in result.dependencies] == ["zlib"]


def _spdx_relationship(element: str, kind: str, related: str) -> dict:
    return {"spdxElementId": element, "relationshipType": kind, "relatedSpdxElement": related}


@pytest.mark.asyncio
async def test_a_trivy_spdx_lock_file_node_is_not_reported_as_dropped():
    """Trivy's SPDX marshaler links the root, its lock-file node and the packages by CONTAINS only."""
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {"name": "/src", "SPDXID": "SPDXRef-Filesystem-1", "primaryPackagePurpose": "SOURCE"},
            {"name": "Gemfile.lock", "SPDXID": "SPDXRef-Application-2", "primaryPackagePurpose": "APPLICATION"},
            {
                "name": "rack",
                "SPDXID": "SPDXRef-Package-3",
                "versionInfo": "3.0.8",
                "primaryPackagePurpose": "LIBRARY",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:gem/rack@3.0.8"}],
            },
        ],
        "relationships": [
            _spdx_relationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Filesystem-1"),
            _spdx_relationship("SPDXRef-Filesystem-1", "CONTAINS", "SPDXRef-Application-2"),
            _spdx_relationship("SPDXRef-Application-2", "CONTAINS", "SPDXRef-Package-3"),
        ],
    }
    request = AdhocAnalyzeRequest(sboms=[sbom], analyzers=["license_compliance"], apply_global_waivers=False)

    response = await run_adhoc_analysis(request, FakeDatabase())

    assert response.analyzers.skipped_inputs == {}
