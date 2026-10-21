import os
import re
from collections.abc import Mapping
from typing import Any, Literal, get_args

from app.models.finding import Severity

# HOSTNAME alone repeats across the processes of one host.
INSTANCE_ID = f"{os.getenv('HOSTNAME', 'unknown')}:{os.getpid()}"

# Keys of the KEV flags on a finding's details and each advisory; every writer and reader of them uses these.
DETAILS_KEY_IN_KEV = "in_kev"
DETAILS_KEY_KEV_RANSOMWARE = "kev_ransomware_use"

# Higher = more severe, in Severity's declaration order; UNKNOWN (0) also ranks any unrecognised label.
SEVERITY_ORDER: dict[str, int] = {level.value: rank for rank, level in enumerate(reversed(Severity))}


def severity_rank_expr(severity: Any) -> dict[str, Any]:
    """Aggregation expression ranking the severity label ``severity`` resolves to, as SEVERITY_ORDER does."""
    return {
        "$switch": {
            "branches": [
                {"case": {"$eq": [severity, label]}, "then": rank} for label, rank in SEVERITY_ORDER.items() if rank
            ],
            "default": 0,
        }
    }


def get_severity_value(severity: str | None) -> int:
    if not severity:
        return 0
    return SEVERITY_ORDER.get(severity.upper(), 0)


def max_severity[S: str | None](*severities: S) -> S:
    return max(severities, key=get_severity_value)


def sort_by_severity[T: Mapping[str, Any]](items: list[T]) -> list[T]:
    return sorted(items, key=lambda item: get_severity_value(item.get("severity")), reverse=True)


EPSS_HIGH_THRESHOLD: float = 0.1
EPSS_MEDIUM_THRESHOLD: float = 0.01


SPDX_GPL_3_0 = "GPL-3.0"
SPDX_GPL_3_0_OR_LATER = "GPL-3.0-or-later"
SPDX_GPL_2_0 = "GPL-2.0"
SPDX_GPL_2_0_OR_LATER = "GPL-2.0-or-later"
SPDX_LGPL_3_0 = "LGPL-3.0"
SPDX_LGPL_2_1 = "LGPL-2.1"
SPDX_LGPL_2_1_OR_LATER = "LGPL-2.1-or-later"
SPDX_LGPL_2_0 = "LGPL-2.0"
SPDX_AGPL_3_0 = "AGPL-3.0"
SPDX_APACHE_2_0 = "Apache-2.0"
SPDX_APACHE_1_1 = "Apache-1.1"
SPDX_MIT = "MIT"
SPDX_BSD_3_CLAUSE = "BSD-3-Clause"
SPDX_BSD_2_CLAUSE = "BSD-2-Clause"
SPDX_MPL_2_0 = "MPL-2.0"
SPDX_MPL_1_1 = "MPL-1.1"

# Matched against the lowercased URL.
LICENSE_URL_PATTERNS: dict[str, str] = {
    # gnu.org keeps the version 2 licences under /old-licenses/.
    r"gnu\.org/licenses/gpl-3\.0": SPDX_GPL_3_0,
    r"gnu\.org/licenses/(old-licenses/)?gpl-2\.0": SPDX_GPL_2_0,
    r"gnu\.org/licenses/lgpl-3\.0": SPDX_LGPL_3_0,
    r"gnu\.org/licenses/(old-licenses/)?lgpl-2\.1": SPDX_LGPL_2_1,
    r"gnu\.org/licenses/(old-licenses/)?lgpl-2\.0": SPDX_LGPL_2_0,
    r"gnu\.org/licenses/agpl-3\.0": SPDX_AGPL_3_0,
    r"apache\.org/licenses/license-2\.0": SPDX_APACHE_2_0,
    r"apache\.org/licenses/license-1\.1": SPDX_APACHE_1_1,
    # opensource.org serves both /licenses/<id> and /license/<id>.
    r"opensource\.org/licenses?/apache-2\.0": SPDX_APACHE_2_0,
    r"opensource\.org/licenses?/mit(?!-0)": SPDX_MIT,
    r"mit-license\.org": SPDX_MIT,
    r"opensource\.org/licenses?/bsd-3-clause": SPDX_BSD_3_CLAUSE,
    r"opensource\.org/licenses?/bsd-2-clause": SPDX_BSD_2_CLAUSE,
    r"opensource\.org/licenses?/isc": "ISC",
    r"creativecommons\.org/licenses/by/4\.0": "CC-BY-4.0",
    r"creativecommons\.org/licenses/by-sa/4\.0": "CC-BY-SA-4.0",
    r"creativecommons\.org/publicdomain/zero/1\.0": "CC0-1.0",
    # mozilla.org may insert a locale segment.
    r"mozilla\.org/([a-z-]+/)?mpl/2\.0": SPDX_MPL_2_0,
    r"mozilla\.org/([a-z-]+/)?mpl/1\.1": SPDX_MPL_1_1,
    r"eclipse\.org/legal/epl-2\.0": "EPL-2.0",
    r"eclipse\.org/legal/epl-v10": "EPL-1.0",
    r"unlicense\.org": "Unlicense",
    r"wtfpl\.net": "WTFPL",
    r"zlib\.net/zlib_license\.html": "Zlib",
}

# Licence names to SPDX ids, beyond the database's own names that normalize_license also accepts.
LICENSE_ALIASES: dict[str, str] = {
    "MIT/X11": SPDX_MIT,
    "Expat": SPDX_MIT,
    "The MIT License": SPDX_MIT,
    "Apache 2": SPDX_APACHE_2_0,
    "Apache 2.0": SPDX_APACHE_2_0,
    "Apache License": SPDX_APACHE_2_0,
    "Apache License 2.0": SPDX_APACHE_2_0,
    "Apache License, Version 2.0": SPDX_APACHE_2_0,
    "Apache License Version 2.0": SPDX_APACHE_2_0,
    "Apache Software License": SPDX_APACHE_2_0,
    "The Apache Software License, Version 2.0": SPDX_APACHE_2_0,
    "The Apache License, Version 2.0": SPDX_APACHE_2_0,
    "ASL 2.0": SPDX_APACHE_2_0,
    "BSD": SPDX_BSD_3_CLAUSE,
    "BSD License": SPDX_BSD_3_CLAUSE,
    "BSD-2": SPDX_BSD_2_CLAUSE,
    "BSD-3": SPDX_BSD_3_CLAUSE,
    "BSD 2-Clause": SPDX_BSD_2_CLAUSE,
    "BSD 3-Clause": SPDX_BSD_3_CLAUSE,
    'BSD 2-Clause "Simplified" License': SPDX_BSD_2_CLAUSE,
    'BSD 3-Clause "New" or "Revised" License': SPDX_BSD_3_CLAUSE,
    "Simplified BSD": SPDX_BSD_2_CLAUSE,
    "New BSD": SPDX_BSD_3_CLAUSE,
    "Modified BSD": SPDX_BSD_3_CLAUSE,
    "GPL": SPDX_GPL_2_0_OR_LATER,
    "GPLv2": SPDX_GPL_2_0,
    "GPLv2+": SPDX_GPL_2_0_OR_LATER,
    "GPLv3": SPDX_GPL_3_0,
    "GPLv3+": SPDX_GPL_3_0_OR_LATER,
    "GPL v2": SPDX_GPL_2_0,
    "GPL v3": SPDX_GPL_3_0,
    "GNU GPL": SPDX_GPL_2_0_OR_LATER,
    "GNU GPLv2": SPDX_GPL_2_0,
    "GNU GPLv3": SPDX_GPL_3_0,
    "GNU General Public License, version 2": SPDX_GPL_2_0,
    "GNU General Public License, version 3": SPDX_GPL_3_0,
    "LGPL": SPDX_LGPL_2_1_OR_LATER,
    "LGPLv2": SPDX_LGPL_2_1,
    "LGPLv2.1": SPDX_LGPL_2_1,
    "LGPL 2.1": SPDX_LGPL_2_1,
    "LGPLv3": SPDX_LGPL_3_0,
    "GNU LGPL": SPDX_LGPL_2_1_OR_LATER,
    "GNU Lesser General Public License": SPDX_LGPL_2_1_OR_LATER,
    "AGPL": SPDX_AGPL_3_0,
    "AGPLv3": SPDX_AGPL_3_0,
    "GNU AGPL": SPDX_AGPL_3_0,
    "MPL": SPDX_MPL_2_0,
    "MPL 1.1": SPDX_MPL_1_1,
    "MPL 2.0": SPDX_MPL_2_0,
    "Mozilla Public License 2.0": SPDX_MPL_2_0,
    # As Maven POMs spell them.
    "EPL 1.0": "EPL-1.0",
    "EPL 2.0": "EPL-2.0",
    "Eclipse Public License - v 1.0": "EPL-1.0",
    "Eclipse Public License - v 2.0": "EPL-2.0",
    "Eclipse Public License v1.0": "EPL-1.0",
    "Eclipse Public License v2.0": "EPL-2.0",
    "CDDL": "CDDL-1.0",
    "Public Domain": "Unlicense",
    "CC0": "CC0-1.0",
    "ISC License": "ISC",
    "Artistic": "Artistic-2.0",
    "zlib/libpng": "Zlib",
    "Boost": "BSL-1.0",
    "PSF": "Python-2.0",
}

UNKNOWN_LICENSE_PATTERNS = {"NOASSERTION", "UNKNOWN", "NONE", "N/A", "NOT FOUND"}

# Project roles, weakest first: the order is the hierarchy.
ProjectRole = Literal["viewer", "editor", "admin"]
PROJECT_ROLE_ADMIN: ProjectRole = "admin"
PROJECT_ROLE_EDITOR: ProjectRole = "editor"
PROJECT_ROLE_VIEWER: ProjectRole = "viewer"
PROJECT_ROLES: list[str] = list(get_args(ProjectRole))

# Each owner costs a read on every project access, and a sync past this many teams has gone wrong.
MAX_PROJECT_TEAMS = 16

# Unattributed entries read as manual, since guessing a provider would let its next sync retire them.
TEAM_SOURCE_MANUAL = "manual"

TEAM_SOURCE_GITLAB = "gitlab"
TEAM_SOURCE_GITHUB = "github"

# Provider plus instance, so two instances of one provider never retire each other's entries; uuid4 has no colon.
TEAM_SOURCE_SEPARATOR = ":"


def team_source(provider: str, instance_id: str) -> str:
    return f"{provider}{TEAM_SOURCE_SEPARATOR}{instance_id}"


def team_binding_key(provider: str, instance_id: str, external_id: int) -> str:
    """One string, so its uniqueness is a single-field equality on its index."""
    return f"{provider}{TEAM_SOURCE_SEPARATOR}{instance_id}{TEAM_SOURCE_SEPARATOR}{external_id}"


POLICY_COMMENT_MAX_LENGTH = 1000
POLICY_CHANGE_SUMMARY_MAX_LENGTH = 200

# Team roles, ordered least- to most-privileged: role checks compare by index.
TeamRole = Literal["member", "admin"]
TEAM_ROLE_ADMIN: TeamRole = "admin"
TEAM_ROLE_MEMBER: TeamRole = "member"
TEAM_ROLES: list[str] = list(get_args(TeamRole))

# Deliberately not the permission vocabulary: permissions decide what a caller may do, a key only which doors it opens.
ApiKeySurface = Literal["mcp", "adhoc"]
API_KEY_SURFACE_MCP: ApiKeySurface = "mcp"
API_KEY_SURFACE_ADHOC: ApiKeySurface = "adhoc"
# The UI shows a key's last use to the minute, so stamping it more often only adds primary writes.
API_KEY_LAST_USED_RESOLUTION_SECONDS = 60

IMPACT_SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
    # Not yet rated rather than harmless: the KEV/EPSS boosts multiply this base.
    "UNKNOWN": 4.0,
}


# npm packages that belong in devDependencies: a dev-only scope, or a tool's name alone or with a "-suffix".
DEV_DEPENDENCY_PATTERN = re.compile(
    r"^(?:@(?:types|testing-library|storybook|commitlint|eslint|typescript-eslint|jest|playwright|cypress|vitest)/.+"
    r"|(?:@[^/]+/)?(?:jest|mocha|chai|sinon|enzyme|eslint|prettier|tslint|stylelint|webpack-dev|nodemon|ts-node"
    r"|typescript|storybook|chromatic|cypress|playwright|puppeteer|husky|lint-staged|commitlint|babel-jest|ts-jest)"
    r"(?:-[\w.-]+)?)$"
)
# Runtime packages that share a dev tool's prefix.
DEV_DEPENDENCY_RUNTIME_PACKAGES = frozenset({"eslint-scope", "jest-worker", "playwright-core", "puppeteer-core"})
NON_RUNTIME_SCOPES = frozenset({"optional", "excluded"})


QUICK_WIN_SCORING_WEIGHTS: dict[str, int] = {
    "base_per_vuln": 10,
    "critical": 50,
    "high": 20,
    "kev": 100,
    "direct_dep_bonus": 50,
}


RECOMMENDATION_SCORING_WEIGHTS: dict[str, int] = {
    "priority_critical": 10000,
    "priority_high": 1000,
    "priority_medium": 100,
    "priority_low": 10,
    "impact_critical": 100,
    "impact_high": 50,
    "impact_medium": 20,
    "impact_low": 5,
    "kev_bonus": 500,
    "kev_ransomware_bonus": 250,
    "high_epss_bonus": 200,
    "medium_epss_bonus": 50,
}


REACHABILITY_SCORING_WEIGHTS: dict[str, int] = {
    "critical_bonus": 150,
    "high_bonus": 75,
    "other_bonus": 25,
}

REACHABILITY_MODIFIERS: dict[str, float] = {
    "high_unreachable_ratio_threshold": 0.8,
    "high_unreachable_penalty": 0.4,
    "medium_unreachable_ratio_threshold": 0.5,
    "medium_unreachable_penalty": 0.7,
}

ACTIONABLE_VULN_BONUS: int = 100

RECOMMENDATION_TYPE_BONUSES: dict[str, int] = {
    "malware_detected": 5000,
    "ransomware_risk": 4000,
    "known_exploit": 3000,
    "actively_exploited": 2500,
    "critical_hotspot": 2000,
    "rotate_secrets": 2000,
    "hash_mismatch": 1800,
    "typosquat_detected": 1500,
    "critical_risk": 1500,
    "base_image_update": 500,
    "single_update_multi_fix": 400,
    "quick_win": 300,
    "toxic_dependency": 250,
    "shared_vulnerability": 200,
    "regression_detected": 150,
    "recurring_vulnerability": 120,
    "direct_dependency_update": 100,
    "fix_infrastructure": 100,
    "license_compliance": 90,
    "eol_dependency": 80,
    "fix_code_security": 80,
    "no_fix_available": 70,
    "supply_chain_risk": 60,
    "transitive_fix_via_parent": 50,
    "outdated_dependency": 40,
    "attack_surface_reduction": 40,
    "cross_project_pattern": 30,
    "version_fragmentation": 20,
    "deep_dependency_chain": 15,
    "duplicate_functionality": 10,
    "dev_in_production": 10,
    # No type bonus: these rank on priority, impact and effort alone.
    "license_drift": 0,
    "replace_weak_algorithm": 0,
    "increase_key_size": 0,
    "upgrade_protocol": 0,
    "pqc_migration": 0,
    "rotate_certificate": 0,
}

EFFORT_BONUSES: dict[str, int] = {
    "low": 50,
    "medium": 20,
    "high": 0,
}

# Dependencies nested deeper than this below their nearest direct dependency are reported.
MAX_DEPENDENCY_DEPTH: int = 5

RECURRING_ISSUE_THRESHOLD: int = 3  # Min scans a CVE appears in to be "recurring"
FINDING_DELTA_THRESHOLD: int = 10
CROSS_PROJECT_MIN_OCCURRENCES: int = 2

EPSS_VERY_HIGH_THRESHOLD: float = 0.5

# Below this a scorecard finding is raised, unless the project sets scorecard_threshold, and graded MEDIUM or worse.
SCORECARD_FLAG_THRESHOLD: float = 5.0
SCORECARD_HIGH_SEVERITY_THRESHOLD: float = 3.0
SCORECARD_POOR_QUALITY_THRESHOLD: float = 4.0

# Days since the last release.
STALE_PACKAGE_THRESHOLD_DAYS: int = 730
STALE_PACKAGE_WARNING_DAYS: int = 365

# unaddressed_issues stays out: a busy tracker on a half-year-quiet repo is no sign of abandonment.
MAINTENANCE_RISK_TYPES = frozenset({"stale_package", "infrequent_updates", "archived_repo", "inactive_repo"})

# Days past an end-of-life date at which the finding is raised to HIGH, then to MEDIUM.
EOL_HIGH_AFTER_DAYS: int = 365
EOL_MEDIUM_AFTER_DAYS: int = 180

TYPOSQUATTING_SIMILARITY_THRESHOLD: float = 0.82
TYPOSQUATTING_HIGH_SIMILARITY: float = 0.90
TYPOSQUATTING_CRITICAL_SIMILARITY: float = 0.95
# A scan-time budget: each 1 000 of the upstream's 15 000 ranks costs ~3 ms per unrecognised component.
TYPOSQUATTING_POPULAR_PACKAGE_RANKS: int = 5000

# A project's analyzers unless overridden; without epss_kev a scan has no in_kev, epss_score or enrichment risk_score.
DEFAULT_ACTIVE_ANALYZERS: tuple[str, ...] = (
    "trivy",
    "osv",
    "license_compliance",
    "end_of_life",
    "epss_kev",
)

# Scanners that run in the CI pipeline; the pipeline reads their switch from the project's analyzers.
CI_SCANNER_ANALYZERS: frozenset[str] = frozenset({"trufflehog", "opengrep", "kics", "bearer", "cbomkit"})

ANALYZER_BATCH_SIZES: dict[str, int] = {
    "osv": 500,
    "deps_dev": 10,
    "outdated": 25,
    "malware": 20,
    "maintainer_risk": 10,
    "hash_verification": 10,
    "end_of_life": 20,
    "epss": 100,  # Max CVEs per EPSS API request
}

ANALYZER_TIMEOUTS: dict[str, float] = {
    "osv": 60.0,
    "deps_dev": 10.0,
    "outdated": 30.0,
    "malware": 30.0,
    "hash_verification": 10.0,
    "maintainer_risk": 15.0,
    "end_of_life": 10.0,
    "typosquatting": 30.0,
    "epss": 30.0,
    "kev": 30.0,
    "ghsa": 15.0,
}

# GitHub allows 5000 requests an hour with a token, 60 without.
GHSA_CONCURRENT_REQUESTS_AUTHENTICATED: int = 10
GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED: int = 2
EPSS_CONCURRENT_BATCHES: int = 4

# "low"/"medium"/"high" are the EPSS buckets; "active" is KEV, "weaponized" KEV with ransomware use.
ExploitMaturity = Literal["unknown", "low", "medium", "high", "active", "weaponized"]

# Higher = more mature, in ExploitMaturity's declaration order.
EXPLOIT_MATURITY_ORDER: dict[ExploitMaturity, int] = {
    level: rank for rank, level in enumerate(get_args(ExploitMaturity))
}

EXPLOIT_MATURITY_BOOST: dict[ExploitMaturity, float] = {
    "weaponized": 1.4,
    "active": 1.3,
    "high": 1.2,
    "medium": 1.1,
    "low": 1.0,
    "unknown": 1.0,
}

# Measured on MongoDB 7: 10 000 rows cost 52 MiB through the graph builder, 200 000 cost 1.04 GiB of a 2 GiB pod.
SCAN_DEPENDENCY_READ_LIMIT: int = 10_000

ANALYTICS_MAX_QUERY_LIMIT: int = 100000

# Projects one analytics scope may hold; the $in of 120 000 ids encodes to 4.8 MiB against the 16 MB BSON limit.
ANALYTICS_MAX_SCOPE_PROJECTS: int = 100_000

# Shared by each REST endpoint and chat tool, so the two entry points cannot bound one read differently.
MAX_CRYPTO_HOTSPOT_PAGE: int = 500
MAX_PQC_PLAN_ITEMS: int = 2000
DEFAULT_PQC_PLAN_ITEMS: int = 500
MAX_COMPLIANCE_REPORT_PAGE: int = 200
MAX_POLICY_AUDIT_PAGE: int = 200


IMPACT_REACH_MULTIPLIER_CAP: int = 10
IMPACT_FIX_AVAILABLE_BOOST: float = 1.2
IMPACT_AGE_BOOST: float = 1.1

KEV_RANSOMWARE_BOOST: float = 3.0
KEV_OVERDUE_BOOST: float = 2.5
KEV_DUE_SOON_BOOST: float = 2.0
KEV_DEFAULT_BOOST: float = 1.8

EPSS_VERY_HIGH_BOOST: float = 1.5
EPSS_HIGH_BOOST: float = 1.3
EPSS_MEDIUM_BOOST: float = 1.1

DAYS_KNOWN_OVERDUE_THRESHOLD: int = 90
BLAST_RADIUS_THRESHOLD: int = 3
KEV_DUE_SOON_DAYS: int = 30

# The largest boost product; every boost is >= 1.0, so fix_impact_score lies in [base, base * IMPACT_MAX_SCORE_BOOST].
IMPACT_MAX_SCORE_BOOST: float = (
    KEV_RANSOMWARE_BOOST
    * EPSS_VERY_HIGH_BOOST
    * max(EXPLOIT_MATURITY_BOOST.values())
    * IMPACT_FIX_AVAILABLE_BOOST
    * IMPACT_AGE_BOOST
)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_API_URL = "https://api.github.com"
GHSA_API_URL = f"{GITHUB_API_URL}/advisories"

# querybatch answers with {id, modified} only; the full record must be fetched per id.
OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_API_URL = "https://api.osv.dev/v1/vulns"

DEPS_DEV_API_URL = "https://api.deps.dev/v3alpha"
PYPI_API_URL = "https://pypi.org/pypi"
NPM_REGISTRY_URL = "https://registry.npmjs.org"

EOL_API_URL = "https://endoflife.date/api"
MALWARE_API_URL = "https://api.opensourcemalware.com/functions/v1/check-malicious"
TOP_PYPI_PACKAGES_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.json"

# A client-registry package with one of these names is a client library, not a release.
SERVER_NAME_TO_EOL_MAPPING: dict[str, str] = {
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "pg": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "opensearch": "opensearch",
    "sqlite": "sqlite",
    "cassandra": "apache-cassandra",
    "couchdb": "apache-couchdb",
    "neo4j": "neo4j",
    "nginx": "nginx",
    "apache": "apache-http-server",
    "httpd": "apache-http-server",
    "tomcat": "tomcat",
    "traefik": "traefik",
    "haproxy": "haproxy",
    "envoy": "envoy",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "docker": "docker-engine",
    "containerd": "containerd",
    "podman": "podman",
    "rabbitmq": "rabbitmq",
    "kafka": "apache-kafka",
    "activemq": "apache-activemq",
    "vault": "hashicorp-vault",
    "consul": "consul",
    "grafana": "grafana",
    "prometheus": "prometheus",
    "kibana": "kibana",
    "logstash": "logstash",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "kong": "kong-gateway",
    "istio": "istio",
}

NAME_TO_EOL_MAPPING: dict[str, str | tuple[str, ...]] = {
    **SERVER_NAME_TO_EOL_MAPPING,
    "python": "python",
    "python3": "python",
    "cpython": "python",
    "node": "nodejs",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "go": "go",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
    "dotnet": "dotnet",
    "dotnet-runtime": "dotnet",
    "dotnet-sdk": "dotnet",
    ".net": "dotnet",
    "rust": "rust",
    "perl": "perl",
    "kotlin": "kotlin",
    "elixir": "elixir",
    "erlang": "erlang",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "rocky-linux": "rocky-linux",
    "almalinux": "almalinux",
    "alpine": "alpine-linux",
    "fedora": "fedora",
    "amazon-linux": "amazon-linux",
    "opensuse": "opensuse",
    "sles": "sles",
    "windows-server": "windows-server",
    # "angular" is AngularJS 1.x as an npm name but Angular 2+ as a CPE product; the cycle match separates them.
    "angular": ("angularjs", "angular"),
    "@angular/core": "angular",
    "react": "react",
    "react-dom": "react",
    "vue": "vue",
    "vue.js": "vue",
    "vuejs": "vue",
    "svelte": "svelte",
    "next": "nextjs",
    "nextjs": "nextjs",
    "next.js": "nextjs",
    "nuxt": "nuxt",
    "nuxt.js": "nuxt",
    "ember": "emberjs",
    "jquery": "jquery",
    "django": "django",
    "rails": "rails",
    "ruby-on-rails": "rails",
    "spring-framework": "spring-framework",
    "spring-boot": "spring-boot",
    "spring": "spring-framework",
    # NVD CPE product that does not normalise to its slug
    "http-server": "apache-http-server",
    "laravel": "laravel",
    "symfony": "symfony",
    "yarn": "yarn",
    "pnpm": "pnpm",
    "maven": "apache-maven",
    "gradle": "gradle",
    "composer": "composer",
    "terraform": "terraform",
    "ansible": "ansible",
    "packer": "hashicorp-packer",
    "numpy": "numpy",
}

SEVERITY_ALIASES: dict[str, str] = {
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
    "TRACE": "INFO",
}

NOTIFICATION_CHANNEL_EMAIL = "email"
NOTIFICATION_CHANNEL_SLACK = "slack"
NOTIFICATION_CHANNEL_MATTERMOST = "mattermost"

NOTIFICATION_CHANNELS = [
    NOTIFICATION_CHANNEL_EMAIL,
    NOTIFICATION_CHANNEL_SLACK,
    NOTIFICATION_CHANNEL_MATTERMOST,
]

NotificationEvent = Literal[
    "analysis_completed",
    "vulnerability_found",
    "analysis_failed",
    "sbom_ingested",
    "crypto_asset_ingested",
    "crypto_policy_changed",
    "license_policy_changed",
    "compliance_report_generated",
]
NOTIFICATION_EVENT_ANALYSIS_COMPLETED: NotificationEvent = "analysis_completed"
NOTIFICATION_EVENT_VULNERABILITY_FOUND: NotificationEvent = "vulnerability_found"
NOTIFICATION_EVENT_ANALYSIS_FAILED: NotificationEvent = "analysis_failed"
NOTIFICATION_EVENT_SBOM_INGESTED: NotificationEvent = "sbom_ingested"
NOTIFICATION_EVENT_CRYPTO_ASSET_INGESTED: NotificationEvent = "crypto_asset_ingested"
NOTIFICATION_EVENT_CRYPTO_POLICY_CHANGED: NotificationEvent = "crypto_policy_changed"
NOTIFICATION_EVENT_LICENSE_POLICY_CHANGED: NotificationEvent = "license_policy_changed"
NOTIFICATION_EVENT_COMPLIANCE_REPORT_GENERATED: NotificationEvent = "compliance_report_generated"

NOTIFICATION_EVENTS: frozenset[str] = frozenset(get_args(NotificationEvent))

SMTP_TIMEOUT_SECONDS: int = 60

SLACK_TOKEN_EXPIRY_BUFFER_SECONDS: int = 300
SLACK_OAUTH_STATE_TTL_SECONDS: int = 600

SIMILAR_PACKAGE_GROUPS: list[dict[str, Any]] = [
    {
        "category": "HTTP Clients",
        "packages": ["axios", "node-fetch", "got", "request", "superagent", "ky"],
        "suggestion": "Consider standardizing on one HTTP client (axios or node-fetch recommended)",
    },
    {
        "category": "Date/Time Libraries",
        "packages": ["moment", "dayjs", "date-fns", "luxon"],
        "suggestion": "Consider using only one date library (dayjs or date-fns recommended)",
    },
    {
        "category": "Utility Libraries",
        "packages": ["lodash", "underscore", "ramda"],
        "suggestion": "Modern JavaScript often doesn't need these - consider native methods",
    },
    {
        "category": "State Management",
        "packages": ["redux", "mobx", "recoil", "zustand", "jotai", "valtio"],
        "suggestion": "Multiple state management libraries may indicate architecture issues",
    },
    {
        "category": "CSS-in-JS",
        "packages": [
            "styled-components",
            "emotion",
            "@emotion/react",
            "glamor",
        ],
        "suggestion": "Standardize on one CSS-in-JS solution",
    },
    {
        "category": "Form Libraries",
        "packages": ["formik", "react-hook-form", "final-form"],
        "suggestion": "Consider using only one form library (react-hook-form recommended)",
    },
    {
        "category": "Testing Assertion",
        "packages": ["chai", "expect", "should", "assert"],
        "suggestion": "Use Jest's built-in expect or standardize on one assertion library",
    },
]

AUTH_PROVIDER_LOCAL = "local"

EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 1

OIDC_STATE_TTL_SECONDS = 300
OIDC_HANDOFF_TTL_SECONDS = 60

TOTP_VALID_WINDOW: int = 1

OIDC_HTTP_TIMEOUT_SECONDS: float = 30.0

WEBHOOK_BACKOFF_BASE: int = 2
WEBHOOK_RESPONSE_BODY_LIMIT_BYTES: int = 64 * 1024  # Only a diagnostic prefix of a receiver's answer is kept

WEBHOOK_EVENT_SCAN_COMPLETED = "scan.completed"
WEBHOOK_EVENT_VULNERABILITY_FOUND = "vulnerability.found"
WEBHOOK_EVENT_ANALYSIS_FAILED = "analysis.failed"
WEBHOOK_EVENT_SBOM_INGESTED = "sbom.ingested"
WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED = "crypto_asset.ingested"
WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED = "crypto_policy.changed"
WEBHOOK_EVENT_LICENSE_POLICY_CHANGED = "license_policy.changed"
WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED = "compliance_report.generated"

# snake_case event names clients may still send; validation stores their canonical form.
WEBHOOK_EVENT_ALIASES: dict[str, str] = {
    "scan_completed": WEBHOOK_EVENT_SCAN_COMPLETED,
    "vulnerability_found": WEBHOOK_EVENT_VULNERABILITY_FOUND,
    "analysis_failed": WEBHOOK_EVENT_ANALYSIS_FAILED,
}

WEBHOOK_VALID_EVENTS = [
    WEBHOOK_EVENT_SCAN_COMPLETED,
    WEBHOOK_EVENT_VULNERABILITY_FOUND,
    WEBHOOK_EVENT_ANALYSIS_FAILED,
    WEBHOOK_EVENT_SBOM_INGESTED,
    WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
    WEBHOOK_EVENT_CRYPTO_POLICY_CHANGED,
    WEBHOOK_EVENT_LICENSE_POLICY_CHANGED,
    WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED,
]

WEBHOOK_ACCEPTED_EVENT_NAMES = [*WEBHOOK_VALID_EVENTS, *WEBHOOK_EVENT_ALIASES.keys()]

WebhookType = Literal["generic", "teams", "slack"]

WEBHOOK_HEADER_CONTENT_TYPE = "Content-Type"
WEBHOOK_HEADER_USER_AGENT = "User-Agent"
WEBHOOK_HEADER_EVENT = "X-Webhook-Event"
WEBHOOK_HEADER_TIMESTAMP = "X-Webhook-Timestamp"
WEBHOOK_HEADER_ID = "X-Webhook-ID"
WEBHOOK_HEADER_SIGNATURE = "X-Webhook-Signature"
WEBHOOK_HEADER_SIGNATURE_V2 = "X-Webhook-Signature-V2"
WEBHOOK_HEADER_DELIVERY = "X-Webhook-Delivery"
WEBHOOK_HEADER_TEST = "X-Webhook-Test"
WEBHOOK_USER_AGENT_VALUE = "DependencyControl-Webhook/1.0"

WEBHOOK_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Cloud-metadata hostnames — never an allowed webhook target.
WEBHOOK_BLOCKED_HOSTNAMES = frozenset({"metadata.google.internal", "metadata.goog", "metadata"})

ScanStatus = Literal["pending", "processing", "completed", "completed_with_errors", "failed"]
SCAN_STATUS_PENDING: ScanStatus = "pending"
SCAN_STATUS_PROCESSING: ScanStatus = "processing"
SCAN_STATUS_COMPLETED: ScanStatus = "completed"
SCAN_STATUS_COMPLETED_WITH_ERRORS: ScanStatus = "completed_with_errors"
SCAN_STATUS_FAILED: ScanStatus = "failed"

SCAN_TYPE_CBOM = "cbom"

# Scans a worker still owns or will claim; housekeeping neither rescans nor deletes them.
SCAN_ACTIVE_STATUSES = [SCAN_STATUS_PENDING, SCAN_STATUS_PROCESSING]

SCAN_USABLE_STATUSES = [
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_COMPLETED_WITH_ERRORS,
]

# BSON dates are milliseconds, so a date-ordered pick of scans tie-breaks on _id, lowest first.
SCANS_TIP_SORT: list[tuple[str, int]] = [("created_at", -1), ("_id", 1)]

FINDINGS_SCAN_SEVERITY_INDEX: dict[str, int] = {"scan_id": 1, "severity": 1, "type": 1, "finding_id": 1}

# Hinted, as unhinted the planner trial-runs each scan_id index to the end; init_db must create them.
FINDINGS_SCAN_TYPE_INDEX: dict[str, int] = {"scan_id": 1, "type": 1}
FINDINGS_SCAN_COMPONENT_INDEX: dict[str, int] = {"scan_id": 1, "component": 1, "version": 1}
DEPENDENCIES_SCAN_PACKAGE_INDEX: dict[str, int] = {"scan_id": 1, "name": 1, "version": 1, "purl": 1}
DEPENDENCIES_SCAN_VERSION_INDEX: dict[str, int] = {"scan_id": 1, "version": 1}

RECENT_UPDATES_LIMIT: int = 30
UpdateKind = Literal["major", "minor", "patch", "unknown", "downgrade"]
# Downgrades are recorded but are not update activity.
COUNTED_UPDATE_KINDS: tuple[UpdateKind, ...] = ("patch", "minor", "major", "unknown")
# A fixed cut order, so a scan with more changes than the limit drops the same ones every time; downgrades last.
UPDATE_SAMPLE_RANK: dict[str, int] = {kind: rank for rank, kind in enumerate(get_args(UpdateKind))}

# Ties at the cap break on the package name, or tied packages swap places between requests.
SLOWEST_PACKAGES_LIMIT: int = 15

# Bounds a rescan-lineage walk so a cyclic pointer cannot hang it; reading the starting scan costs no hop.
MAX_RESCAN_HOPS: int = 10

SPDX_ORGANIZATION_PREFIX = "Organization:"

SOURCE_TYPE_IMAGE = "image"
SOURCE_TYPE_APPLICATION = "application"
SOURCE_TYPE_FILE = "file"
SOURCE_TYPE_DIRECTORY = "directory"

OS_PACKAGE_TYPES = frozenset(
    {
        "deb",
        "rpm",
        "apk",
        "alpm",
        "pacman",
        "dpkg",
        "yum",
        "dnf",
        "apt",
    }
)

APP_PACKAGE_TYPES = frozenset(
    {
        "npm",
        "pypi",
        "maven",
        "cargo",
        "gem",
        "nuget",
        "golang",
        "composer",
        "hex",
        "cocoapods",
        "swift",
        "pub",
        "hackage",
    }
)

REACHABILITY_LEVEL_NONE = "none"
REACHABILITY_LEVEL_IMPORT = "import"
REACHABILITY_LEVEL_SYMBOL = "symbol"

REACHABILITY_CONFIDENCE_NOT_USED = 0.9
REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS = 0.5
REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO = 0.4
REACHABILITY_CONFIDENCE_SYMBOL_MATCHED = 1.0
# Vulnerable symbols searched and none used directly: weaker evidence than having no symbol data.
REACHABILITY_CONFIDENCE_SYMBOLS_NOT_USED = 0.35

# Below this a reachable verdict still counts but may show as needs verification, typically an import-only match.
REACHABILITY_HIGH_CONFIDENCE_THRESHOLD = 0.6

GITLAB_ACCESS_REPORTER = 20
GITLAB_ACCESS_MAINTAINER = 40

GITLAB_ADMIN_MIN_ACCESS = GITLAB_ACCESS_MAINTAINER
# Guest and Minimal Access members cannot read a group's code, so they own none of its projects.
GITLAB_TEAM_MEMBER_MIN_ACCESS = GITLAB_ACCESS_REPORTER

AGG_KEY_VULNERABILITY = "AGG:VULN"
AGG_KEY_QUALITY = "AGG:QUALITY"

# Cross-linking is pairwise, so a larger group is left unlinked rather than paying O(n^2) for an unusable list.
MAX_CROSS_LINK_GROUP_SIZE: int = 100

WaiverStatus = Literal["accepted_risk", "false_positive"]
WAIVER_STATUS_ACCEPTED_RISK: WaiverStatus = "accepted_risk"
WAIVER_STATUS_FALSE_POSITIVE: WaiverStatus = "false_positive"

# "finding" = exact match, "file" = same rule in the same file, "rule" = same rule project-wide.
WaiverScope = Literal["finding", "file", "rule"]
WAIVER_SCOPE_FINDING: WaiverScope = "finding"
WAIVER_SCOPE_FILE: WaiverScope = "file"
WAIVER_SCOPE_RULE: WaiverScope = "rule"

# A waiver change restamps only the tips of branches built within this many days.
WAIVER_RESTAMP_BRANCH_ACTIVE_DAYS: int = 30

CVSS_SEVERITY_SCORES: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "NEGLIGIBLE": 0.0,
    "INFO": 0.0,
    # The midpoint calculate_risk_score assumes for a CVE without a CVSS score.
    "UNKNOWN": 5.0,
}

# calculate_risk_score's CVSS share, so unenriched findings sit on the same scale as enriched ones.
SEVERITY_CALCULATED_RISK_SCORES: dict[str, float] = {
    sev: round((cvss / 10.0) * 40.0, 1) for sev, cvss in CVSS_SEVERITY_SCORES.items()
}

JWKS_CACHE_TTL = 3600
JWKS_URI_CACHE_TTL = 86400

# GitLab answers a non-admin token's GET /users/:id 300 times per 10 minutes, and public emails rarely change.
GITLAB_USER_EMAIL_CACHE_TTL = 86400

# One workflow run fans out into many jobs; without this every job refetches the same three lists.
GITHUB_TEAM_SYNC_CACHE_TTL = 300

# Every job of every pipeline ingests, so a project's GitLab ownership is resolved once per window.
GITLAB_TEAM_SYNC_WINDOW_SECONDS = 600

# Profile emails rarely change, and each is a request per member of every holding team.
GITHUB_USER_EMAIL_CACHE_TTL = 21600

# One request per organisation team: at an hour the map spends ~313 of the token's 5000 hourly requests.
GITHUB_ORG_REPO_MAP_CACHE_TTL = 3600

# calculate_risk_score of a CVSS 9.0 CVE at EPSS_HIGH_THRESHOLD; a CVE outside KEV scores at most 65.
HIGH_RISK_SCORE_THRESHOLD: float = 56.0

# Quiet seconds after a scan's last result before it is analysed, tuned to typical CI pipeline timing.
HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS: int = 30

HOUSEKEEPING_MAX_SCAN_RETRIES: int = 3

ANALYSIS_MAX_RETRIES: int = 5

HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS: int = 10

HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS: int = 300

HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS: int = 24

HOUSEKEEPING_BRANCH_SYNC_INTERVAL_HOURS: int = 6

# Night in europe-west1, so the reconcile's repair writes stay out of the working day.
HOUSEKEEPING_UPDATE_FREQUENCY_RECONCILE_HOUR_UTC: int = 2

# Rescans each build keeps, failed ones included; older runs are near-identical full copies of the same SBOM.
RESCAN_HISTORY_RUNS: int = 7

# Only the insert runs under this lock.
HOUSEKEEPING_RESCAN_LOCK_TTL_SECONDS: int = 60

RetentionAction = Literal["delete", "archive", "none"]
RETENTION_ACTION_DELETE: RetentionAction = "delete"
RETENTION_ACTION_ARCHIVE: RetentionAction = "archive"
RETENTION_ACTION_NONE: RetentionAction = "none"

RETENTION_ACTIONS: list[str] = list(get_args(RetentionAction))

DEFAULT_RETENTION_DAYS: int = 90
# timedelta overflows near 740 000 days, and a cutoff housekeeping cannot compute stops the sweep.
MAX_RETENTION_DAYS: int = 36500

ScopeName = Literal["project", "team", "global", "user"]

SettingsMode = Literal["project", "global"]
SETTINGS_MODE_PROJECT: SettingsMode = "project"
SETTINGS_MODE_GLOBAL: SettingsMode = "global"

ARCHIVE_BUNDLE_VERSION = 2
ARCHIVE_PATH_TEMPLATE = "{project_id}/{scan_id}-{archived_at_unix}.bundle"
# ARCHIVE_PATH_TEMPLATE's shape: the orphan reaper deletes no other key, so a shared bucket keeps foreign objects.
ARCHIVE_KEY_PATTERN = r"[^/]+/(?P<scan_id>[^/]+)-\d+\.bundle"
ARCHIVE_RESTORE_LOCK_TEMPLATE = "restore:{scan_id}"
REACHABILITY_LOCK_TEMPLATE = "reachability:{scan_id}"

ENCRYPTION_MAGIC = b"DCEN"
ENCRYPTION_FORMAT_VERSION = 2
ENCRYPTION_CHUNK_SIZE = 8 * 1024 * 1024

S3_MULTIPART_PART_SIZE = 5 * 1024 * 1024 + 256 * 1024  # S3 parts other than the last must be at least 5 MiB

RESTORE_INSERT_BATCH_SIZE = 1000

ARCHIVE_BATCH_SIZE = 50

# Every collection a scan owns by a scan_id field; deletion, archival and restore must all read this one list.
SCAN_SCOPED_COLLECTIONS: tuple[str, ...] = (
    "analysis_results",
    "findings",
    "finding_records",
    "dependencies",
    "callgraphs",
    "crypto_assets",
)

# Keyed by scan id rather than a scan_id field; archive bundles leave them out, as the restore recomputes them.
SCAN_KEYED_COLLECTIONS: tuple[str, ...] = ("scan_update_deltas", "scan_outdated_sets")

# Bundle sections of the scan's GridFS files: whole SBOMs (older bundles, still restored) and ordered file chunks.
ARCHIVE_GRIDFS_FRAME = "gridfs_sboms"
ARCHIVE_GRIDFS_CHUNK_FRAME = "gridfs_chunks"

# A flag written outside the model as int32 1 satisfies {"$ne": True}, so the guards name both spellings.
RETENTION_PROTECTED_FLAG_VALUES: list[object] = [True, 1]

# Scan ids per round trip of the release-flag reconcile; both directions splice one into an $in.
RELEASE_FLAG_RECONCILE_BATCH_SIZE = 1000

# Uploads precede the document that references them, so the S3, callgraph and GridFS reapers spare younger ones.
ORPHAN_MIN_AGE_HOURS = 24

ADHOC_JOB_TTL_SECONDS: int = 24 * 3600

MAX_CONCURRENT_COMPLIANCE_REPORTS: int = 10
# Per process; at ~55 MiB per saturated report, 2 slots x 2 workers stay near 220 MiB of the 2 GiB pod limit.
COMPLIANCE_REPORT_SLOTS: int = 2
# Generation runs as an in-process background task, so a report this old lost its pod mid-run.
COMPLIANCE_REPORT_STUCK_AFTER_HOURS: int = 6
CRYPTO_ASSET_BULK_CHUNK_SIZE: int = 500

# Environments are used as index and query keys, so the slug shape is enforced, not normalised.
RELEASE_ENVIRONMENT_PATTERN: str = r"^[a-z0-9][a-z0-9_-]{0,31}$"
DEFAULT_RELEASE_ENVIRONMENT: str = "production"
# Docker's tag limit, so a version that doubles as the image tag always fits.
RELEASE_VERSION_MAX_LENGTH: int = 128


def validate_release_environment(value: str | None) -> str | None:
    if value is None:
        return None
    if not re.fullmatch(RELEASE_ENVIRONMENT_PATTERN, value):
        raise ValueError(f"release_environment must match {RELEASE_ENVIRONMENT_PATTERN}")
    return value
