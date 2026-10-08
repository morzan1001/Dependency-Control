"""Licence names, URLs and comma-bearing titles as SBOM generators write them resolve to SPDX ids."""

import asyncio
import itertools
from typing import Any

import pytest

from app.core.constants import LICENSE_ALIASES, LICENSE_URL_PATTERNS
from app.services.analyzers.license_compliance.analyzer import LicenseAnalyzer
from app.services.analyzers.license_compliance.constants import LICENSE_DATABASE
from app.services.analyzers.license_compliance.constants import LICENSE_INCOMPATIBILITIES
from app.services.analyzers.license_compliance import normalizer
from app.services.analyzers.license_compliance.normalizer import (
    extract_license_from_url,
    normalize_license,
    parse_license_expression,
    split_license_list,
    tokenize_license_string,
)
from app.services.sbom_parser import SBOMParser, parse_sbom


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://www.apache.org/licenses/LICENSE-2.0.txt", "Apache-2.0"),
        ("http://www.apache.org/licenses/LICENSE-1.1", "Apache-1.1"),
        ("https://opensource.org/licenses/MIT", "MIT"),
        ("https://opensource.org/license/mit/", "MIT"),
        ("https://mit-license.org", "MIT"),
        ("https://opensource.org/licenses/BSD-3-Clause", "BSD-3-Clause"),
        ("https://opensource.org/license/bsd-2-clause", "BSD-2-Clause"),
        ("https://opensource.org/licenses/ISC", "ISC"),
        ("https://www.gnu.org/licenses/gpl-3.0.html", "GPL-3.0"),
        ("https://www.gnu.org/licenses/old-licenses/gpl-2.0.html", "GPL-2.0"),
        ("https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html", "LGPL-2.1"),
        ("https://www.gnu.org/licenses/old-licenses/lgpl-2.0.html", "LGPL-2.0"),
        ("https://www.gnu.org/licenses/lgpl-3.0.html", "LGPL-3.0"),
        ("https://www.gnu.org/licenses/agpl-3.0.html", "AGPL-3.0"),
        ("https://www.mozilla.org/en-US/MPL/2.0/", "MPL-2.0"),
        ("https://www.mozilla.org/MPL/1.1/", "MPL-1.1"),
        ("https://www.eclipse.org/legal/epl-2.0/", "EPL-2.0"),
        ("https://www.eclipse.org/legal/epl-v10.html", "EPL-1.0"),
        ("https://creativecommons.org/publicdomain/zero/1.0/", "CC0-1.0"),
    ],
)
def test_a_canonical_licence_url_resolves_to_a_known_id(url, expected):
    assert extract_license_from_url(url) == expected
    assert expected in LICENSE_DATABASE


def test_every_licence_the_vocabulary_names_is_one_the_database_knows():
    named = {
        *LICENSE_URL_PATTERNS.values(),
        *LICENSE_ALIASES.values(),
        *itertools.chain.from_iterable(LICENSE_INCOMPATIBILITIES),
    }
    assert {lic for lic in named if lic not in LICENSE_DATABASE} == set()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("MIT License", "MIT"),
        ("The MIT License", "MIT"),
        ("Apache License", "Apache-2.0"),
        ("Apache Software License", "Apache-2.0"),
        ("The Apache Software License, Version 2.0", "Apache-2.0"),
        ("Apache License Version 2.0", "Apache-2.0"),
        ("Apache 2", "Apache-2.0"),
        ("Eclipse Public License 2.0", "EPL-2.0"),
        ("Eclipse Public License v2.0", "EPL-2.0"),
        ("Eclipse Public License - v 2.0", "EPL-2.0"),
        ("Eclipse Public License - v 1.0", "EPL-1.0"),
        ("EPL 2.0", "EPL-2.0"),
        ("BSD 2-Clause", "BSD-2-Clause"),
        ("BSD 3-Clause License", "BSD-3-Clause"),
        ('BSD 3-Clause "New" or "Revised" License', "BSD-3-Clause"),
        ("GNU General Public License, version 2", "GPL-2.0"),
        ("GNU General Public License v3.0 only", "GPL-3.0-only"),
        ("GNU Lesser General Public License", "LGPL-2.1-or-later"),
        ("Common Development and Distribution License 1.0", "CDDL-1.0"),
        ("CDDL", "CDDL-1.0"),
        ("Python Software Foundation License 2.0", "PSF-2.0"),
        ("Unicode License Agreement - Data Files and Software (2016)", "Unicode-DFS-2016"),
    ],
)
def test_a_verbose_licence_name_resolves_to_its_spdx_id(name, expected):
    assert normalize_license(name) == expected


def test_a_licence_title_with_a_comma_stays_one_licence():
    assert parse_license_expression("Apache License, Version 2.0, MIT") == [["Apache-2.0", "MIT"]]
    assert tokenize_license_string("Apache License, Version 2.0") == ["Apache-2.0"]


def test_splitting_a_long_licence_list_normalizes_each_part_a_bounded_number_of_times(monkeypatch):
    # PyPI License: metadata can carry a whole licence text with hundreds of commas.
    parts = [f"clause {i}" for i in range(1000)]
    calls = 0

    def counting_normalize(lic_id: str) -> str:
        nonlocal calls
        calls += 1
        return normalize_license(lic_id)

    monkeypatch.setattr(normalizer, "normalize_license", counting_normalize)

    assert split_license_list(", ".join(parts)) == parts
    assert calls <= 5 * len(parts)


def test_syft_prefers_the_spdx_expression_it_resolved_over_the_raw_value():
    entry = {"value": "GPL-2.0+", "spdxExpression": "GPL-2.0-or-later", "type": "declared"}
    assert SBOMParser()._handle_syft_license_dict(entry) == ("GPL-2.0-or-later", None)


def _analyze(licenses: list[dict[str, Any]]) -> dict[str, Any]:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "lib", "version": "1.0", "licenses": licenses}],
    }
    components = [dep.model_dump() for dep in parse_sbom(sbom).dependencies]
    result: dict[str, Any] = asyncio.run(LicenseAnalyzer().analyze(sbom, parsed_components=components))
    return result


@pytest.mark.parametrize(
    "licenses",
    [
        [{"license": {"name": "https://www.apache.org/licenses/LICENSE-2.0.txt"}}],
        [{"license": {"url": "https://www.apache.org/licenses/LICENSE-2.0.txt"}}],
        [{"license": {"name": "Apache License, Version 2.0"}}],
        [{"license": {"name": "The MIT License", "url": "https://opensource.org/licenses/MIT"}}],
        [{"license": {"name": "MIT-style", "url": "https://opensource.org/licenses/MIT"}}],
    ],
)
def test_a_permissive_component_is_classified_not_undeterminable(licenses):
    result = _analyze(licenses)

    assert result["summary"]["permissive"] == 1
    assert result["summary"]["unknown"] == 0


def test_an_old_licenses_gpl_url_raises_the_copyleft_finding():
    result = _analyze([{"license": {"name": "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"}}])

    assert result["summary"]["strong_copyleft"] == 1


@pytest.mark.parametrize(
    ("spdx_id", "category", "severity"),
    [
        ("BUSL-1.1", "proprietary", "HIGH"),
        ("Elastic-2.0", "proprietary", "HIGH"),
        ("CC-BY-NC-SA-4.0", "proprietary", "HIGH"),
        ("OSL-3.0", "network_copyleft", "CRITICAL"),
        ("EUPL-1.2", "strong_copyleft", "HIGH"),
    ],
)
def test_a_common_spdx_licence_gets_the_verdict_of_its_category(spdx_id, category, severity):
    result = _analyze([{"license": {"id": spdx_id}}])

    assert [(i["license"], i["category"], i["severity"]) for i in result["license_issues"]] == [
        (spdx_id, category, severity)
    ]


@pytest.mark.parametrize("licence", ["PSF-2.0", "MIT-0", "Unicode-DFS-2016"])
def test_a_common_permissive_licence_raises_no_finding(licence):
    result = _analyze([{"license": {"name": licence}}])

    assert result["summary"]["permissive"] == 1
    assert result["license_issues"] == []


def test_an_id_outside_the_catalogue_is_reported_as_a_catalogue_gap():
    (issue,) = _analyze([{"license": {"id": "Glide"}}])["license_issues"]

    assert issue["explanation"] == (
        "The SBOM declares Glide for this component, which is not in the license catalogue this analyzer "
        "evaluates, so its obligations cannot be evaluated."
    )
