"""Constants for the license-compliance analyzer."""

from __future__ import annotations

from dataclasses import replace

from app.core.constants import (
    SEVERITY_ORDER,
    SPDX_AGPL_3_0,
    SPDX_GPL_2_0,
    SPDX_GPL_2_0_OR_LATER,
    SPDX_GPL_3_0,
    SPDX_GPL_3_0_OR_LATER,
    SPDX_LGPL_2_0,
    SPDX_LGPL_2_1,
    SPDX_LGPL_3_0,
)
from app.models.finding import Severity
from app.models.license import LicenseCategory, LicenseInfo

INCLUDE_COPYRIGHT_NOTICE = "Include copyright notice"
INCLUDE_LICENSE_TEXT = "Include license text"
SHARE_SOURCE_OF_MODIFICATIONS = "Share source of library modifications"
SHARE_SOURCE_OF_MODIFIED_FILES = "Share source of modified files"
USE_GPL_FOR_DERIVATIVE_WORK = "Use GPL for derivative work"
SHARE_COMPLETE_SOURCE_CODE = "Share complete source code"
NETWORK_USE_TRIGGERS_DISCLOSURE = "Network use triggers source disclosure"
NOT_DESIGNED_FOR_SOFTWARE = "Not designed for software"
NON_COMMERCIAL_USE_ONLY = "Non-commercial use only"
CANNOT_USE_IN_COMMERCIAL_PRODUCTS = "Cannot use in commercial products"

# Stands in for the licence of a component the SBOM does not let us determine.
UNDETERMINED_LICENSE_ID = "UNKNOWN"
UNDETERMINED_LICENSE_MESSAGE = "License could not be determined from the SBOM"

SPDX_GPL_2_0_ONLY = "GPL-2.0-only"
SPDX_GPL_3_0_ONLY = "GPL-3.0-only"
SPDX_AGPL_3_0_ONLY = "AGPL-3.0-only"
SPDX_CDDL_1_0 = "CDDL-1.0"
SPDX_EPL_1_0 = "EPL-1.0"
SPDX_SSPL_1_0 = "SSPL-1.0"

_GPL_V3_FAMILY = (SPDX_GPL_3_0_ONLY, SPDX_GPL_3_0_OR_LATER, SPDX_AGPL_3_0_ONLY, "AGPL-3.0-or-later")
_GPL_FAMILY = (SPDX_GPL_2_0_ONLY, SPDX_GPL_2_0_OR_LATER, *_GPL_V3_FAMILY)

# Keyed by CANONICAL_LICENSE_ID forms; GPL-2.0-or-later is absent from the v3 rule because GPLv3 satisfies it.
LICENSE_INCOMPATIBILITIES: dict[frozenset[str], str] = {
    **{
        frozenset({SPDX_GPL_2_0_ONLY, gpl_v3}): (
            f"{SPDX_GPL_2_0_ONLY} and {gpl_v3} are not compatible — code cannot satisfy both simultaneously."
        )
        for gpl_v3 in _GPL_V3_FAMILY
    },
    **{
        frozenset({copyleft, gpl}): f"{copyleft} and {gpl} are incompatible due to conflicting copyleft terms."
        for copyleft in (SPDX_CDDL_1_0, "CDDL-1.1", SPDX_EPL_1_0)
        for gpl in _GPL_FAMILY
    },
    **{
        frozenset({SPDX_SSPL_1_0, gpl}): f"{SPDX_SSPL_1_0} is not compatible with any GPL version."
        for gpl in _GPL_FAMILY
    },
}

# Every policy escape in evaluate_license lands below HIGH, so HIGH is the first rank policy did not soften.
POLICY_VIOLATION_MIN_RANK = SEVERITY_ORDER[Severity.HIGH.value]


LICENSE_DATABASE: dict[str, LicenseInfo] = {
    "MIT": LicenseInfo(
        spdx_id="MIT",
        category=LicenseCategory.PERMISSIVE,
        name="MIT License",
        description="Very permissive license allowing almost any use with attribution.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "Apache-2.0": LicenseInfo(
        spdx_id="Apache-2.0",
        category=LicenseCategory.PERMISSIVE,
        name="Apache License 2.0",
        description="Permissive license with patent grant protection.",
        obligations=[
            INCLUDE_COPYRIGHT_NOTICE,
            INCLUDE_LICENSE_TEXT,
            "State changes",
            "Include NOTICE file if present",
        ],
    ),
    "Apache-1.1": LicenseInfo(
        spdx_id="Apache-1.1",
        category=LicenseCategory.PERMISSIVE,
        name="Apache License 1.1",
        description="Permissive license with an end-user acknowledgement clause.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT, "Include the acknowledgement in documentation"],
    ),
    "BSD-2-Clause": LicenseInfo(
        spdx_id="BSD-2-Clause",
        category=LicenseCategory.PERMISSIVE,
        name="BSD 2-Clause License",
        description="Simple permissive license with minimal requirements.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "BSD-3-Clause": LicenseInfo(
        spdx_id="BSD-3-Clause",
        category=LicenseCategory.PERMISSIVE,
        name="BSD 3-Clause License",
        description="Permissive license with non-endorsement clause.",
        obligations=[
            INCLUDE_COPYRIGHT_NOTICE,
            INCLUDE_LICENSE_TEXT,
            "No endorsement without permission",
        ],
    ),
    "ISC": LicenseInfo(
        spdx_id="ISC",
        category=LicenseCategory.PERMISSIVE,
        name="ISC License",
        description="Simplified permissive license similar to MIT.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
    ),
    "Unlicense": LicenseInfo(
        spdx_id="Unlicense",
        category=LicenseCategory.PUBLIC_DOMAIN,
        name="The Unlicense",
        description="Public domain dedication with no restrictions.",
        risks=["May not be recognized in all jurisdictions"],
    ),
    "CC0-1.0": LicenseInfo(
        spdx_id="CC0-1.0",
        category=LicenseCategory.PUBLIC_DOMAIN,
        name="CC0 1.0 Universal",
        description="Public domain dedication by Creative Commons.",
    ),
    "0BSD": LicenseInfo(
        spdx_id="0BSD",
        category=LicenseCategory.PUBLIC_DOMAIN,
        name="Zero-Clause BSD",
        description="Public domain equivalent BSD license.",
    ),
    "WTFPL": LicenseInfo(
        spdx_id="WTFPL",
        category=LicenseCategory.PUBLIC_DOMAIN,
        name="Do What The F*ck You Want To Public License",
        description="Extremely permissive, essentially public domain.",
        risks=["May not be legally enforceable in all jurisdictions"],
    ),
    "LGPL-2.0-only": LicenseInfo(
        spdx_id="LGPL-2.0-only",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="GNU Library General Public License v2 only",
        description="The predecessor of LGPL 2.1 with the same library copyleft.",
        obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Allow relinking"],
        risks=["Static linking may trigger full GPL terms"],
    ),
    "LGPL-2.0-or-later": LicenseInfo(
        spdx_id="LGPL-2.0-or-later",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="GNU Library General Public License v2 or later",
        description="LGPL 2.0 with option to use later versions.",
        obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Allow relinking"],
        risks=["Static linking may trigger full GPL terms"],
    ),
    "LGPL-2.1-only": LicenseInfo(
        spdx_id="LGPL-2.1-only",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="GNU Lesser General Public License v2.1 only",
        description="Allows linking in proprietary software, but library changes must be shared.",
        obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Allow relinking (for dynamic linking)", INCLUDE_LICENSE_TEXT],
        risks=["Static linking may trigger full GPL terms"],
    ),
    "LGPL-2.1-or-later": LicenseInfo(
        spdx_id="LGPL-2.1-or-later",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="GNU Lesser General Public License v2.1 or later",
        description="LGPL 2.1 with option to use later versions.",
        obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Allow relinking"],
    ),
    "LGPL-3.0-only": LicenseInfo(
        spdx_id="LGPL-3.0-only",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="GNU Lesser General Public License v3.0 only",
        description="Modern LGPL with better patent protection.",
        obligations=[SHARE_SOURCE_OF_MODIFICATIONS, "Provide installation information", INCLUDE_LICENSE_TEXT],
        risks=["Must allow user to replace library version"],
    ),
    "LGPL-3.0-or-later": LicenseInfo(
        spdx_id="LGPL-3.0-or-later",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="GNU Lesser General Public License v3.0 or later",
        description="LGPL 3.0 with option to use later versions.",
        obligations=[SHARE_SOURCE_OF_MODIFICATIONS],
        risks=[],
    ),
    "MPL-2.0": LicenseInfo(
        spdx_id="MPL-2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Mozilla Public License 2.0",
        description="File-level copyleft - only modified files must be shared.",
        obligations=[
            SHARE_SOURCE_OF_MODIFIED_FILES,
            INCLUDE_LICENSE_TEXT,
            "Preserve copyright notices",
        ],
        risks=[],
    ),
    "MPL-1.1": LicenseInfo(
        spdx_id="MPL-1.1",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Mozilla Public License 1.1",
        description="File-level copyleft; unlike MPL 2.0 not compatible with the GPL.",
        obligations=[SHARE_SOURCE_OF_MODIFIED_FILES, INCLUDE_LICENSE_TEXT, "Preserve copyright notices"],
    ),
    SPDX_EPL_1_0: LicenseInfo(
        spdx_id=SPDX_EPL_1_0,
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Eclipse Public License 1.0",
        description="Weak copyleft with patent grant.",
        obligations=["Share source of modifications"],
        risks=["Patent retaliation clause"],
    ),
    "EPL-2.0": LicenseInfo(
        spdx_id="EPL-2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Eclipse Public License 2.0",
        description="Modern EPL with GPL compatibility option.",
        obligations=["Share source of modifications"],
        risks=[],
    ),
    SPDX_CDDL_1_0: LicenseInfo(
        spdx_id=SPDX_CDDL_1_0,
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Common Development and Distribution License 1.0",
        description="File-level copyleft similar to MPL.",
        obligations=[SHARE_SOURCE_OF_MODIFIED_FILES],
        risks=["Incompatible with GPL"],
    ),
    "CDDL-1.1": LicenseInfo(
        spdx_id="CDDL-1.1",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Common Development and Distribution License 1.1",
        description="File-level copyleft similar to MPL; CDDL 1.0 with patent and jurisdiction updates.",
        obligations=[SHARE_SOURCE_OF_MODIFIED_FILES],
        risks=["Incompatible with GPL"],
    ),
    "MS-RL": LicenseInfo(
        spdx_id="MS-RL",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Microsoft Reciprocal License",
        description="File-level copyleft - modified files must be shared under MS-RL.",
        obligations=[SHARE_SOURCE_OF_MODIFIED_FILES, INCLUDE_LICENSE_TEXT],
    ),
    "GPL-1.0-only": LicenseInfo(
        spdx_id="GPL-1.0-only",
        category=LicenseCategory.STRONG_COPYLEFT,
        name="GNU General Public License v1.0 only",
        description="The first GPL - entire derivative work must use GPL 1.0 when distributed.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
        risks=["Cannot be combined with proprietary code if distributed"],
    ),
    "GPL-1.0-or-later": LicenseInfo(
        spdx_id="GPL-1.0-or-later",
        category=LicenseCategory.STRONG_COPYLEFT,
        name="GNU General Public License v1.0 or later",
        description="GPL 1.0 with option to use later versions.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
    ),
    SPDX_GPL_2_0_ONLY: LicenseInfo(
        spdx_id=SPDX_GPL_2_0_ONLY,
        category=LicenseCategory.STRONG_COPYLEFT,
        name="GNU General Public License v2.0 only",
        description="Strong copyleft - entire derivative work must use GPL 2.0 when distributed, with no 'or later' option.",
        obligations=[
            SHARE_COMPLETE_SOURCE_CODE,
            USE_GPL_FOR_DERIVATIVE_WORK,
            INCLUDE_LICENSE_TEXT,
            "Include installation instructions",
        ],
        risks=[
            "Cannot be combined with proprietary code if distributed",
            "Source code must be provided to recipients",
            "Cannot use GPL-3.0-only code",
        ],
    ),
    SPDX_GPL_2_0_OR_LATER: LicenseInfo(
        spdx_id=SPDX_GPL_2_0_OR_LATER,
        category=LicenseCategory.STRONG_COPYLEFT,
        name="GNU General Public License v2.0 or later",
        description="GPL 2.0 with option to use later versions.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
        risks=[],
    ),
    SPDX_GPL_3_0_ONLY: LicenseInfo(
        spdx_id=SPDX_GPL_3_0_ONLY,
        category=LicenseCategory.STRONG_COPYLEFT,
        name="GNU General Public License v3.0 only",
        description="Modern GPL with patent protection and anti-tivoization, with no 'or later' option.",
        obligations=[
            SHARE_COMPLETE_SOURCE_CODE,
            USE_GPL_FOR_DERIVATIVE_WORK,
            "Provide installation information",
            "No additional restrictions (DRM, etc.)",
        ],
        risks=[
            "Cannot be combined with proprietary code",
            "Anti-tivoization may affect embedded devices",
            "Incompatible with GPL-2.0-only",
        ],
    ),
    SPDX_GPL_3_0_OR_LATER: LicenseInfo(
        spdx_id=SPDX_GPL_3_0_OR_LATER,
        category=LicenseCategory.STRONG_COPYLEFT,
        name="GNU General Public License v3.0 or later",
        description="GPL 3.0 with option to use later versions.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, USE_GPL_FOR_DERIVATIVE_WORK],
        risks=[],
    ),
    "EUPL-1.1": LicenseInfo(
        spdx_id="EUPL-1.1",
        category=LicenseCategory.STRONG_COPYLEFT,
        name="European Union Public License 1.1",
        description="The European Commission's copyleft; derivatives may move to a listed compatible licence.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, "Use EUPL or a listed compatible license for derivative work"],
    ),
    "EUPL-1.2": LicenseInfo(
        spdx_id="EUPL-1.2",
        category=LicenseCategory.STRONG_COPYLEFT,
        name="European Union Public License 1.2",
        description="EUPL 1.1 with a longer compatibility list, including GPL-3.0 and AGPL-3.0.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, "Use EUPL or a listed compatible license for derivative work"],
    ),
    "Sleepycat": LicenseInfo(
        spdx_id="Sleepycat",
        category=LicenseCategory.STRONG_COPYLEFT,
        name="Sleepycat License",
        description="Berkeley DB's license - redistributing software that uses it requires offering its complete source.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE],
        risks=["Cannot be combined with proprietary code if distributed"],
    ),
    "AGPL-1.0-only": LicenseInfo(
        spdx_id="AGPL-1.0-only",
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="Affero General Public License v1.0 only",
        description="The first Affero GPL, GPL 2.0 extended to network services.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, "Provide source access to network users"],
        risks=[NETWORK_USE_TRIGGERS_DISCLOSURE],
    ),
    "AGPL-1.0-or-later": LicenseInfo(
        spdx_id="AGPL-1.0-or-later",
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="Affero General Public License v1.0 or later",
        description="AGPL 1.0 with option to use later versions.",
        obligations=[SHARE_COMPLETE_SOURCE_CODE, "Provide source access to network users"],
        risks=[NETWORK_USE_TRIGGERS_DISCLOSURE],
    ),
    SPDX_AGPL_3_0_ONLY: LicenseInfo(
        spdx_id=SPDX_AGPL_3_0_ONLY,
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="GNU Affero General Public License v3.0 only",
        description="GPL-3.0 extended to network services - must share source if users interact over network.",
        obligations=[
            SHARE_COMPLETE_SOURCE_CODE,
            "Provide source access to network users",
            "Use AGPL for derivative work",
        ],
        risks=[
            NETWORK_USE_TRIGGERS_DISCLOSURE,
            "SaaS and web services must provide source",
            "Very restrictive for commercial use",
        ],
    ),
    "AGPL-3.0-or-later": LicenseInfo(
        spdx_id="AGPL-3.0-or-later",
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="GNU Affero General Public License v3.0 or later",
        description="AGPL 3.0 with option to use later versions.",
        obligations=["Share source to network users"],
        risks=[NETWORK_USE_TRIGGERS_DISCLOSURE],
    ),
    "CPAL-1.0": LicenseInfo(
        spdx_id="CPAL-1.0",
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="Common Public Attribution License 1.0",
        description="MPL-based copyleft whose source and attribution duties extend to network use.",
        obligations=[SHARE_SOURCE_OF_MODIFIED_FILES, "Show the attribution notice to network users"],
        risks=[NETWORK_USE_TRIGGERS_DISCLOSURE],
    ),
    "RPL-1.5": LicenseInfo(
        spdx_id="RPL-1.5",
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="Reciprocal Public License 1.5",
        description="Copyleft that requires publishing modifications even when they are only deployed.",
        obligations=["Publish source of modifications, including deployed ones"],
        risks=[NETWORK_USE_TRIGGERS_DISCLOSURE, "Internal deployment may trigger disclosure"],
    ),
    "OSL-3.0": LicenseInfo(
        spdx_id="OSL-3.0",
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="Open Software License 3.0",
        description="Copyleft whose External Deployment clause treats network use as distribution.",
        obligations=["Share source of derivative works", "Use OSL for derivative work"],
        risks=[NETWORK_USE_TRIGGERS_DISCLOSURE, "Incompatible with GPL"],
    ),
    SPDX_SSPL_1_0: LicenseInfo(
        spdx_id=SPDX_SSPL_1_0,
        category=LicenseCategory.NETWORK_COPYLEFT,
        name="Server Side Public License v1",
        description="MongoDB's license - even stricter than AGPL for SaaS use.",
        obligations=[
            "Share all service code including management software",
            "Extends to entire service stack",
        ],
        risks=[
            "Extremely restrictive for cloud/SaaS",
            "Not OSI approved",
            "May require sharing unrelated service code",
        ],
    ),
    "CC-BY-4.0": LicenseInfo(
        spdx_id="CC-BY-4.0",
        category=LicenseCategory.PERMISSIVE,
        name="Creative Commons Attribution 4.0",
        description="Attribution required. Typically for non-software content.",
        obligations=["Give appropriate credit", "Indicate if changes were made"],
        risks=[NOT_DESIGNED_FOR_SOFTWARE],
    ),
    "CC-BY-SA-4.0": LicenseInfo(
        spdx_id="CC-BY-SA-4.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        name="Creative Commons Attribution ShareAlike 4.0",
        description="Attribution + ShareAlike - derivatives must use same license.",
        obligations=["Give credit", "Use same license for derivatives"],
        risks=[NOT_DESIGNED_FOR_SOFTWARE, "ShareAlike can be restrictive"],
    ),
    "CC-BY-NC-4.0": LicenseInfo(
        spdx_id="CC-BY-NC-4.0",
        category=LicenseCategory.PROPRIETARY,
        name="Creative Commons Attribution NonCommercial 4.0",
        description="Cannot be used commercially.",
        obligations=["Give credit", NON_COMMERCIAL_USE_ONLY],
        risks=[CANNOT_USE_IN_COMMERCIAL_PRODUCTS],
    ),
    "CC-BY-NC-SA-4.0": LicenseInfo(
        spdx_id="CC-BY-NC-SA-4.0",
        category=LicenseCategory.PROPRIETARY,
        name="Creative Commons Attribution NonCommercial ShareAlike 4.0",
        description="Cannot be used commercially; adaptations must use the same license.",
        obligations=["Give credit", NON_COMMERCIAL_USE_ONLY, "Use same license for derivatives"],
        risks=[CANNOT_USE_IN_COMMERCIAL_PRODUCTS],
    ),
    "CC-BY-NC-ND-4.0": LicenseInfo(
        spdx_id="CC-BY-NC-ND-4.0",
        category=LicenseCategory.PROPRIETARY,
        name="Creative Commons Attribution NonCommercial NoDerivatives 4.0",
        description="Cannot be used commercially, and adapted versions may not be shared.",
        obligations=["Give credit", NON_COMMERCIAL_USE_ONLY, "Share no adapted versions"],
        risks=[CANNOT_USE_IN_COMMERCIAL_PRODUCTS],
    ),
    "CC-BY-ND-4.0": LicenseInfo(
        spdx_id="CC-BY-ND-4.0",
        category=LicenseCategory.PROPRIETARY,
        name="Creative Commons Attribution NoDerivatives 4.0",
        description="Commercial use is allowed, but adapted versions may not be shared.",
        obligations=["Give credit", "Share no adapted versions"],
        risks=["Cannot ship a modified version"],
    ),
    "BUSL-1.1": LicenseInfo(
        spdx_id="BUSL-1.1",
        category=LicenseCategory.PROPRIETARY,
        name="Business Source License 1.1",
        description=(
            "Source-available: production use needs the licensor's Additional Use Grant or a commercial license "
            "until the change date, when the code becomes open source."
        ),
        obligations=["Stay within the Additional Use Grant"],
        risks=["Production use may require a commercial license"],
    ),
    "Elastic-2.0": LicenseInfo(
        spdx_id="Elastic-2.0",
        category=LicenseCategory.PROPRIETARY,
        name="Elastic License 2.0",
        description="Source-available: may not be offered as a managed service or have its license keys bypassed.",
        obligations=["Do not provide the software as a managed service", "Do not circumvent license keys"],
        risks=["Cannot be offered to third parties as a managed service"],
    ),
    "Artistic-2.0": LicenseInfo(
        spdx_id="Artistic-2.0",
        category=LicenseCategory.PERMISSIVE,
        name="Artistic License 2.0",
        description="Perl's license - permissive with some restrictions on modified versions.",
        obligations=[
            "Document modifications",
            "Use different name for modified versions",
        ],
        risks=[],
    ),
    "Zlib": LicenseInfo(
        spdx_id="Zlib",
        category=LicenseCategory.PERMISSIVE,
        name="zlib License",
        description="Very permissive license used by zlib compression library.",
        obligations=["Acknowledge in documentation"],
        risks=[],
    ),
    "BSL-1.0": LicenseInfo(
        spdx_id="BSL-1.0",
        category=LicenseCategory.PERMISSIVE,
        name="Boost Software License 1.0",
        description="Very permissive license from Boost C++ Libraries.",
        obligations=["Include license text in source distributions"],
        risks=[],
    ),
    "Python-2.0": LicenseInfo(
        spdx_id="Python-2.0",
        category=LicenseCategory.PERMISSIVE,
        name="Python License 2.0",
        description="Python's permissive license.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
        risks=[],
    ),
    "PostgreSQL": LicenseInfo(
        spdx_id="PostgreSQL",
        category=LicenseCategory.PERMISSIVE,
        name="PostgreSQL License",
        description="BSD-style permissive license.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
        risks=[],
    ),
    "PSF-2.0": LicenseInfo(
        spdx_id="PSF-2.0",
        category=LicenseCategory.PERMISSIVE,
        name="Python Software Foundation License 2.0",
        description="The Python Software Foundation's permissive license.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "Python-2.0.1": LicenseInfo(
        spdx_id="Python-2.0.1",
        category=LicenseCategory.PERMISSIVE,
        name="Python License 2.0.1",
        description="Python's permissive license in its revised wording.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
    ),
    "MIT-0": LicenseInfo(
        spdx_id="MIT-0",
        category=LicenseCategory.PERMISSIVE,
        name="MIT No Attribution",
        description="MIT without the attribution requirement.",
    ),
    "BlueOak-1.0.0": LicenseInfo(
        spdx_id="BlueOak-1.0.0",
        category=LicenseCategory.PERMISSIVE,
        name="Blue Oak Model License 1.0.0",
        description="Modern permissive license with an explicit patent grant.",
        obligations=[INCLUDE_LICENSE_TEXT],
    ),
    "Unicode-DFS-2016": LicenseInfo(
        spdx_id="Unicode-DFS-2016",
        category=LicenseCategory.PERMISSIVE,
        name="Unicode License Agreement - Data Files and Software (2016)",
        description="Permissive license for Unicode data files and software.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
    ),
    "Unicode-3.0": LicenseInfo(
        spdx_id="Unicode-3.0",
        category=LicenseCategory.PERMISSIVE,
        name="Unicode License v3",
        description="Permissive license for Unicode data files and software.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
    ),
    "BSD-4-Clause": LicenseInfo(
        spdx_id="BSD-4-Clause",
        category=LicenseCategory.PERMISSIVE,
        name="BSD 4-Clause License",
        description="The original BSD license with its advertising clause.",
        obligations=[
            INCLUDE_COPYRIGHT_NOTICE,
            INCLUDE_LICENSE_TEXT,
            "Acknowledge the authors in advertising materials",
        ],
        risks=["Advertising clause is incompatible with the GPL"],
    ),
    "OpenSSL": LicenseInfo(
        spdx_id="OpenSSL",
        category=LicenseCategory.PERMISSIVE,
        name="OpenSSL License",
        description="BSD-style license with advertising and naming clauses.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, "Acknowledge OpenSSL in advertising materials"],
        risks=["Advertising clause is incompatible with the GPL"],
    ),
    "curl": LicenseInfo(
        spdx_id="curl",
        category=LicenseCategory.PERMISSIVE,
        name="curl License",
        description="MIT-style license of the curl project.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
    ),
    "X11": LicenseInfo(
        spdx_id="X11",
        category=LicenseCategory.PERMISSIVE,
        name="X11 License",
        description="MIT variant with a non-endorsement clause.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "HPND": LicenseInfo(
        spdx_id="HPND",
        category=LicenseCategory.PERMISSIVE,
        name="Historical Permission Notice and Disclaimer",
        description="Early permissive license similar to MIT.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE],
    ),
    "ICU": LicenseInfo(
        spdx_id="ICU",
        category=LicenseCategory.PERMISSIVE,
        name="ICU License",
        description="MIT-style license of the ICU project.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "NCSA": LicenseInfo(
        spdx_id="NCSA",
        category=LicenseCategory.PERMISSIVE,
        name="University of Illinois/NCSA Open Source License",
        description="BSD-style permissive license with a non-endorsement clause.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "UPL-1.0": LicenseInfo(
        spdx_id="UPL-1.0",
        category=LicenseCategory.PERMISSIVE,
        name="Universal Permissive License v1.0",
        description="Permissive license with an explicit patent grant.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, INCLUDE_LICENSE_TEXT],
    ),
    "OFL-1.1": LicenseInfo(
        spdx_id="OFL-1.1",
        category=LicenseCategory.PERMISSIVE,
        name="SIL Open Font License 1.1",
        description="Font license: the fonts may ship with any software but not be sold on their own.",
        obligations=[INCLUDE_COPYRIGHT_NOTICE, "Do not sell the fonts by themselves"],
    ),
    "CC-BY-3.0": LicenseInfo(
        spdx_id="CC-BY-3.0",
        category=LicenseCategory.PERMISSIVE,
        name="Creative Commons Attribution 3.0 Unported",
        description="Attribution required. Typically for non-software content.",
        obligations=["Give appropriate credit", "Indicate if changes were made"],
        risks=[NOT_DESIGNED_FOR_SOFTWARE],
    ),
}

_DEPRECATED_NAMES = {
    "GPL-1.0": "GNU General Public License v1.0",
    SPDX_GPL_2_0: "GNU General Public License v2.0",
    SPDX_GPL_3_0: "GNU General Public License v3.0",
    SPDX_LGPL_2_0: "GNU Library General Public License v2",
    SPDX_LGPL_2_1: "GNU Lesser General Public License v2.1",
    SPDX_LGPL_3_0: "GNU Lesser General Public License v3.0",
    "AGPL-1.0": "Affero General Public License v1.0",
    SPDX_AGPL_3_0: "GNU Affero General Public License v3.0",
}
# SPDX deprecated these ids in favour of their -only form, which is what they mean.
CANONICAL_LICENSE_ID = {deprecated: f"{deprecated}-only" for deprecated in _DEPRECATED_NAMES}
LICENSE_DATABASE.update(
    {
        deprecated: replace(LICENSE_DATABASE[canonical], spdx_id=deprecated, name=_DEPRECATED_NAMES[deprecated])
        for deprecated, canonical in CANONICAL_LICENSE_ID.items()
    }
)


CATEGORY_STAT_KEY: dict[LicenseCategory, str] = {
    LicenseCategory.PERMISSIVE: "permissive",
    LicenseCategory.PUBLIC_DOMAIN: "permissive",
    LicenseCategory.WEAK_COPYLEFT: "weak_copyleft",
    LicenseCategory.STRONG_COPYLEFT: "strong_copyleft",
    LicenseCategory.NETWORK_COPYLEFT: "network_copyleft",
    LicenseCategory.PROPRIETARY: "proprietary",
}
