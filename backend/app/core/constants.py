"""
Shared Constants

Centralized constants used across the application to ensure consistency.
"""

from typing import Any, Dict, List, Optional

# Severity order for sorting (higher value = more severe)
SEVERITY_ORDER: Dict[str, int] = {
    # Uppercase variants for consistency
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "NEGLIGIBLE": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def get_severity_value(severity: Optional[str]) -> int:
    """Get numeric value for severity. Higher = more severe."""
    if not severity:
        return 0
    return SEVERITY_ORDER.get(severity.upper(), 0)


def sort_by_severity(items: list, key: str = "severity", reverse: bool = True) -> list:
    """
    Sort a list of dicts by severity.

    Args:
        items: List of dicts with severity field
        key: The key containing severity value
        reverse: If True, most severe first (default)
    """
    return sorted(
        items,
        key=lambda x: get_severity_value(
            x.get(key) if isinstance(x, dict) else getattr(x, key, None)
        ),
        reverse=reverse,
    )


# EPSS score thresholds based on exploitation probability
EPSS_HIGH_THRESHOLD: float = 0.1  # >= 10% - Very likely to be exploited
EPSS_MEDIUM_THRESHOLD: float = 0.01  # >= 1% - Moderate exploitation risk
EPSS_LOW_THRESHOLD: float = 0.0  # < 1% - Low exploitation risk


# License URL Patterns
# Common license URL patterns to SPDX ID mapping
LICENSE_URL_PATTERNS: Dict[str, str] = {
    # GNU Licenses
    r"gnu\.org/licenses/gpl-3\.0": "GPL-3.0",
    r"gnu\.org/licenses/gpl-2\.0": "GPL-2.0",
    r"gnu\.org/licenses/lgpl-3\.0": "LGPL-3.0",
    r"gnu\.org/licenses/lgpl-2\.1": "LGPL-2.1",
    r"gnu\.org/licenses/lgpl-2\.0": "LGPL-2.0",
    r"gnu\.org/licenses/agpl-3\.0": "AGPL-3.0",
    r"gnu\.org/licenses/fdl": "GFDL-1.3",
    # Apache
    r"apache\.org/licenses/LICENSE-2\.0": "Apache-2.0",
    r"apache\.org/licenses/LICENSE-1\.1": "Apache-1.1",
    # MIT
    r"opensource\.org/licenses/MIT": "MIT",
    r"mit-license\.org": "MIT",
    # BSD
    r"opensource\.org/licenses/BSD-3-Clause": "BSD-3-Clause",
    r"opensource\.org/licenses/BSD-2-Clause": "BSD-2-Clause",
    # Creative Commons
    r"creativecommons\.org/licenses/by/4\.0": "CC-BY-4.0",
    r"creativecommons\.org/licenses/by-sa/4\.0": "CC-BY-SA-4.0",
    r"creativecommons\.org/publicdomain/zero/1\.0": "CC0-1.0",
    # Mozilla
    r"mozilla\.org/MPL/2\.0": "MPL-2.0",
    r"mozilla\.org/MPL/1\.1": "MPL-1.1",
    # Eclipse
    r"eclipse\.org/legal/epl-2\.0": "EPL-2.0",
    r"eclipse\.org/legal/epl-v10": "EPL-1.0",
    # ISC
    r"opensource\.org/licenses/ISC": "ISC",
    # Unlicense
    r"unlicense\.org": "Unlicense",
    # WTFPL
    r"wtfpl\.net": "WTFPL",
    # Zlib
    r"zlib\.net/zlib_license\.html": "Zlib",
}

# License Aliases
# Common license names to SPDX ID mapping
LICENSE_ALIASES: Dict[str, str] = {
    "MIT/X11": "MIT",
    "Expat": "MIT",
    # Apache variations
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "ASL 2.0": "Apache-2.0",
    # BSD variations
    "BSD": "BSD-3-Clause",
    "BSD License": "BSD-3-Clause",
    "BSD-2": "BSD-2-Clause",
    "BSD-3": "BSD-3-Clause",
    "Simplified BSD": "BSD-2-Clause",
    "New BSD": "BSD-3-Clause",
    "Modified BSD": "BSD-3-Clause",
    # GPL variations
    "GPL": "GPL-2.0-or-later",
    "GPLv2": "GPL-2.0",
    "GPLv2+": "GPL-2.0-or-later",
    "GPLv3": "GPL-3.0",
    "GPLv3+": "GPL-3.0-or-later",
    "GPL v2": "GPL-2.0",
    "GPL v3": "GPL-3.0",
    "GNU GPL": "GPL-2.0-or-later",
    "GNU GPLv2": "GPL-2.0",
    "GNU GPLv3": "GPL-3.0",
    # LGPL variations
    "LGPL": "LGPL-2.1-or-later",
    "LGPLv2": "LGPL-2.1",
    "LGPLv2.1": "LGPL-2.1",
    "LGPLv3": "LGPL-3.0",
    "GNU LGPL": "LGPL-2.1-or-later",
    # AGPL variations
    "AGPL": "AGPL-3.0",
    "AGPLv3": "AGPL-3.0",
    "GNU AGPL": "AGPL-3.0",
    # MPL variations
    "MPL": "MPL-2.0",
    "MPL 2.0": "MPL-2.0",
    "Mozilla Public License 2.0": "MPL-2.0",
    # Other
    "Public Domain": "Unlicense",
    "CC0": "CC0-1.0",
    "ISC License": "ISC",
    "Artistic": "Artistic-2.0",
    "zlib/libpng": "Zlib",
    "Boost": "BSL-1.0",
    "PSF": "Python-2.0",
}

# Patterns indicating unknown/missing license
UNKNOWN_LICENSE_PATTERNS = {
    "NOASSERTION",
    "UNKNOWN",
    "NONE",
    "N/A",
    "NOT FOUND",
    "UNLICENSED",
    "SEE LICENSE",
    "CUSTOM",
    "PROPRIETARY",
}

# Project Roles
PROJECT_ROLE_ADMIN = "admin"
PROJECT_ROLE_EDITOR = "editor"
PROJECT_ROLE_VIEWER = "viewer"
PROJECT_ROLES = [PROJECT_ROLE_VIEWER, PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN]

# Team Roles
TEAM_ROLE_OWNER = "owner"
TEAM_ROLE_ADMIN = "admin"
TEAM_ROLE_MEMBER = "member"
TEAM_ROLES = [TEAM_ROLE_MEMBER, TEAM_ROLE_ADMIN, TEAM_ROLE_OWNER]


# ==============================================================================
# RECOMMENDATION ENGINE CONSTANTS
# ==============================================================================

# Weights for calculating risk scores (supports both uppercase and lowercase keys)
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
    "UNKNOWN": 0.0,
    # Lowercase variants for compatibility
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.0,
    "unknown": 0.0,
}

# Common patterns for development dependencies
DEV_DEPENDENCY_PATTERNS = [
    r"jest",
    r"mocha",
    r"chai",
    r"sinon",
    r"enzyme",
    r"testing-library",
    r"eslint",
    r"prettier",
    r"tslint",
    r"stylelint",
    r"webpack-dev",
    r"nodemon",
    r"ts-node",
    r"@types/",
    r"typescript$",
    r"storybook",
    r"chromatic",
    r"cypress",
    r"playwright",
    r"puppeteer",
    r"husky",
    r"lint-staged",
    r"commitlint",
    r"babel-jest",
    r"ts-jest",
]


# Scoring weights for identifying "Quick Win" updates
QUICK_WIN_SCORING_WEIGHTS: Dict[str, int] = {
    "base_per_vuln": 10,
    "critical": 50,
    "high": 20,
    "kev": 100,
    "direct_dep_bonus": 50,
}


# Weights for calculating recommendation priority scores
RECOMMENDATION_SCORING_WEIGHTS: Dict[str, int] = {
    # Base priority scores
    "priority_critical": 10000,
    "priority_high": 1000,
    "priority_medium": 100,
    "priority_low": 10,
    # Impact multipliers
    "impact_critical": 100,
    "impact_high": 50,
    "impact_medium": 20,
    "impact_low": 5,
    # Threat intel bonuses
    "kev_bonus": 500,
    "kev_ransomware_bonus": 250,
    "high_epss_bonus": 200,
    "medium_epss_bonus": 50,
    "active_exploitation_bonus": 300,
}


# Weights for reachability analysis
REACHABILITY_SCORING_WEIGHTS: Dict[str, int] = {
    "critical_bonus": 150,
    "high_bonus": 75,
    "other_bonus": 25,
}

REACHABILITY_MODIFIERS: Dict[str, float] = {
    "high_unreachable_ratio_threshold": 0.8,
    "high_unreachable_penalty": 0.4,
    "medium_unreachable_ratio_threshold": 0.5,
    "medium_unreachable_penalty": 0.7,
}

# Bonus for actionable vulnerabilities
ACTIONABLE_VULN_BONUS: int = 100

# Type-based bonuses for recommendation scoring
# Higher values = higher priority in the recommendation list
RECOMMENDATION_TYPE_BONUSES: Dict[str, int] = {
    # Critical security issues - highest priority
    "malware_detected": 5000,
    "ransomware_risk": 4000,
    "known_exploit": 3000,
    "actively_exploited": 2500,
    "critical_hotspot": 2000,
    "rotate_secrets": 2000,
    "typosquat_detected": 1500,
    "critical_risk": 1500,
    # High impact updates
    "base_image_update": 500,
    "single_update_multi_fix": 400,
    "quick_win": 300,
    "toxic_dependency": 250,
    "shared_vulnerability": 200,
    # Regression/recurring - important to address
    "regression_detected": 150,
    "recurring_vulnerability": 120,
    # Standard updates
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
    # Low priority hygiene
    "version_fragmentation": 20,
    "deep_dependency_chain": 15,
    "duplicate_functionality": 10,
    "dev_in_production": 10,
}

# Effort-based bonuses (lower effort = higher bonus)
EFFORT_BONUSES: Dict[str, int] = {
    "low": 50,
    "medium": 20,
    "high": 0,
}


# ==============================================================================
# RECOMMENDATION ENGINE CONFIGURATION
# ==============================================================================

# Maximum depth for dependency chain analysis
MAX_DEPENDENCY_DEPTH: int = 5

# Threshold for considering a dependency outdated (in days)
OUTDATED_DEPENDENCY_THRESHOLD_DAYS: int = 365 * 2  # 2 years

# Thresholds for recommendation analysis
RECURRING_ISSUE_THRESHOLD: int = 3  # Min scans a CVE appears in to be "recurring"
FINDING_DELTA_THRESHOLD: int = 10  # Min new findings to trigger regression warning
MIN_VULNS_FOR_RECOMMENDATION: int = 3  # Min vulns to generate certain recommendations
SIGNIFICANT_FRAGMENTATION_THRESHOLD: int = 3  # Min version count to be significant
CROSS_PROJECT_MIN_OCCURRENCES: int = 2  # Min projects for cross-project patterns

# EPSS very high threshold (for immediate action recommendations)
EPSS_VERY_HIGH_THRESHOLD: float = 0.5  # >= 50% - Extremely likely to be exploited

# OpenSSF Scorecard thresholds
SCORECARD_LOW_THRESHOLD: float = 4.0  # Packages below this are flagged as low quality
SCORECARD_UNMAINTAINED_THRESHOLD: float = 5.0  # Used for critical risk correlation


# System Permissions - Use Permissions class from app.core.permissions instead
# These are kept for backwards compatibility but should be migrated to use Permissions.*
# from app.core.permissions import Permissions


# ==============================================================================
# ANALYZER THRESHOLDS
# ==============================================================================

# OpenSSF Scorecard thresholds (use these instead of SCORECARD_THRESHOLD):
# - SCORECARD_LOW_THRESHOLD (4.0): Packages flagged as low quality (high risk)
# - SCORECARD_UNMAINTAINED_THRESHOLD (5.0): General warning threshold

# Maintainer risk thresholds (days since last release)
STALE_PACKAGE_THRESHOLD_DAYS: int = 730  # 2 years = potentially abandoned
STALE_PACKAGE_WARNING_DAYS: int = 365  # 1 year = warning

# Typosquatting detection threshold (similarity ratio 0-1)
TYPOSQUATTING_SIMILARITY_THRESHOLD: float = 0.82

# Analyzer batch sizes for API rate limiting
ANALYZER_BATCH_SIZES: Dict[str, int] = {
    "osv": 500,
    "deps_dev": 10,
    "outdated": 25,
    "malware": 20,
    "maintainer_risk": 10,
    "typosquatting": 50,
    "end_of_life": 20,
    "epss": 100,  # Max CVEs per EPSS API request
}

# Analyzer HTTP timeouts (seconds)
ANALYZER_TIMEOUTS: Dict[str, float] = {
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
    "default": 30.0,
}

# Retry configuration for enrichment providers is now in settings.py
# Use settings.ENRICHMENT_MAX_RETRIES and settings.ENRICHMENT_RETRY_DELAY

# GHSA concurrent fetching (with GitHub token: 5000 req/hour, without: 60 req/hour)
GHSA_CONCURRENT_REQUESTS_AUTHENTICATED: int = 10
GHSA_CONCURRENT_REQUESTS_UNAUTHENTICATED: int = 2

# Exploit maturity levels for risk prioritization (higher = more severe)
EXPLOIT_MATURITY_ORDER: Dict[str, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "poc": 4,  # Proof of concept
    "active": 5,
    "weaponized": 6,
}

# Exploit maturity boost factors for impact score calculation
EXPLOIT_MATURITY_BOOST: Dict[str, float] = {
    "weaponized": 1.4,
    "active": 1.3,
    "high": 1.2,
    "medium": 1.1,
    "low": 1.0,
    "unknown": 1.0,
}


# ==============================================================================
# ANALYTICS CONSTANTS
# ==============================================================================

# Maximum items returned by analytics aggregation queries
# Used to prevent memory issues with large datasets
ANALYTICS_MAX_QUERY_LIMIT: int = 100000

# Impact score calculation parameters
IMPACT_REACH_MULTIPLIER_CAP: int = 10  # Max multiplier for affected projects
IMPACT_FIX_AVAILABLE_BOOST: float = 1.2  # Boost for issues with available fixes
IMPACT_AGE_BOOST: float = 1.1  # Boost for vulnerabilities known > 90 days

# KEV boost factors for impact calculation
KEV_RANSOMWARE_BOOST: float = 3.0  # Used in ransomware campaigns
KEV_OVERDUE_BOOST: float = 2.5  # CISA deadline overdue
KEV_DUE_SOON_BOOST: float = 2.0  # Due within 30 days
KEV_DEFAULT_BOOST: float = 1.8  # Any KEV entry

# EPSS boost factors for impact calculation
EPSS_VERY_HIGH_BOOST: float = 1.5  # >= 50% exploitation probability
EPSS_HIGH_BOOST: float = 1.3  # >= 10% exploitation probability
EPSS_MEDIUM_BOOST: float = 1.1  # >= 1% exploitation probability

# Thresholds for priority reasons in analytics
DAYS_KNOWN_OVERDUE_THRESHOLD: int = 90  # Days a vuln is known before flagged as overdue
BLAST_RADIUS_THRESHOLD: int = 3  # Min affected projects for "high blast radius"
KEV_DUE_SOON_DAYS: int = 30  # Days until KEV deadline to be "due soon"

# Severity weights for impact score calculation (deprecated - use SEVERITY_WEIGHTS instead)
IMPACT_SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
}


# ==============================================================================
# EXTERNAL SERVICE URLS
# ==============================================================================

# Threat intelligence
EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_API_URL = "https://api.github.com/advisories"

# Vulnerability databases
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"

# Package metadata APIs
DEPS_DEV_API_URL = "https://api.deps.dev/v3alpha"
PYPI_API_URL = "https://pypi.org/pypi"
NPM_REGISTRY_URL = "https://registry.npmjs.org"

# Other service APIs
EOL_API_URL = "https://endoflife.date/api"
MALWARE_API_URL = "https://api.opensourcemalware.com/functions/v1/check-malicious"
TOP_PYPI_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"
)
GITHUB_API_URL = "https://api.github.com"


# ==============================================================================
# END-OF-LIFE MAPPING
# ==============================================================================

# Mapping from package/component names to endoflife.date product IDs
# See https://endoflife.date/api for all available products
NAME_TO_EOL_MAPPING: Dict[str, str] = {
    # Programming Languages & Runtimes
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
    "java": "java",
    "openjdk": "java",
    "dotnet": "dotnet",
    "dotnet-runtime": "dotnet",
    "dotnet-sdk": "dotnet",
    ".net": "dotnet",
    "rust": "rust",
    "perl": "perl",
    "swift": "swift",
    "kotlin": "kotlin",
    "elixir": "elixir",
    "erlang": "erlang",
    # Databases
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
    "couchdb": "couchdb",
    "neo4j": "neo4j",
    # Web Servers & Proxies
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "tomcat": "apache-tomcat",
    "traefik": "traefik",
    "haproxy": "haproxy",
    "envoy": "envoy",
    # Container & Orchestration
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "docker": "docker",
    "containerd": "containerd",
    "podman": "podman",
    "helm": "helm",
    # Operating Systems
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "rocky-linux": "rocky-linux",
    "almalinux": "almalinux",
    "alpine": "alpine",
    "fedora": "fedora",
    "amazon-linux": "amazon-linux",
    "opensuse": "opensuse",
    "sles": "sles",
    "windows-server": "windows-server",
    # Frontend Frameworks
    "angular": "angular",
    "@angular/core": "angular",
    "react": "react",
    "react-dom": "react",
    "vue": "vuejs",
    "vue.js": "vuejs",
    "vuejs": "vuejs",
    "svelte": "svelte",
    "next": "nextjs",
    "nextjs": "nextjs",
    "next.js": "nextjs",
    "nuxt": "nuxt",
    "nuxt.js": "nuxt",
    "gatsby": "gatsby",
    "ember": "emberjs",
    "jquery": "jquery",
    # Backend Frameworks
    "django": "django",
    "flask": "flask",
    "fastapi": "fastapi",
    "rails": "rails",
    "ruby-on-rails": "rails",
    "spring-framework": "spring-framework",
    "spring-boot": "spring-boot",
    "spring": "spring-framework",
    "laravel": "laravel",
    "symfony": "symfony",
    "express": "nodejs",
    "nestjs": "nestjs",
    "fastify": "fastify",
    "gin": "gin",
    "echo": "echo",
    "actix": "actix-web",
    # Build Tools & Package Managers
    "npm": "npm",
    "yarn": "yarn",
    "pnpm": "pnpm",
    "pip": "pip",
    "maven": "maven",
    "gradle": "gradle",
    "composer": "composer",
    "bundler": "bundler",
    "cargo": "cargo",
    # Cloud & Infrastructure
    "terraform": "terraform",
    "ansible": "ansible",
    "pulumi": "pulumi",
    "vagrant": "vagrant",
    "packer": "packer",
    "vault": "hashicorp-vault",
    "consul": "consul",
    # Message Queues
    "rabbitmq": "rabbitmq",
    "kafka": "apache-kafka",
    "activemq": "apache-activemq",
    "nats": "nats-server",
    # ML/AI Frameworks
    "tensorflow": "tensorflow",
    "pytorch": "pytorch",
    "keras": "keras",
    "scikit-learn": "scikit-learn",
    "pandas": "pandas",
    "numpy": "numpy",
    # Other Tools
    "grafana": "grafana",
    "prometheus": "prometheus",
    "kibana": "kibana",
    "logstash": "logstash",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "github-enterprise": "github-enterprise-server",
    "kong": "kong-gateway",
    "istio": "istio",
    "linkerd": "linkerd",
}


# ==============================================================================
# SCANNER SEVERITY MAPPINGS
# ==============================================================================

# Severity aliases for normalizing different scanner output formats
# Used by safe_severity() in normalizers/utils.py
SEVERITY_ALIASES: Dict[str, str] = {
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
    "TRACE": "INFO",
}

# KICS (IaC scanner) severity mapping
KICS_SEVERITY_MAP: Dict[str, str] = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "TRACE": "INFO",
}

# OpenGrep/Semgrep (SAST scanner) severity mapping
OPENGREP_SEVERITY_MAP: Dict[str, str] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

# Bearer (SAST scanner) severity mapping
BEARER_SEVERITY_MAP: Dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "warning": "LOW",
    "info": "INFO",
}


# ==============================================================================
# NOTIFICATION CONSTANTS
# ==============================================================================

# Notification channel identifiers
NOTIFICATION_CHANNEL_EMAIL = "email"
NOTIFICATION_CHANNEL_SLACK = "slack"
NOTIFICATION_CHANNEL_MATTERMOST = "mattermost"

NOTIFICATION_CHANNELS = [
    NOTIFICATION_CHANNEL_EMAIL,
    NOTIFICATION_CHANNEL_SLACK,
    NOTIFICATION_CHANNEL_MATTERMOST,
]

# SMTP timeout in seconds
SMTP_TIMEOUT_SECONDS: int = 60

# Slack token expiry buffer in seconds (refresh 5 minutes before expiry)
SLACK_TOKEN_EXPIRY_BUFFER_SECONDS: int = 300

# HTTP timeout for notification providers is now in settings.py
# Use settings.NOTIFICATION_HTTP_TIMEOUT_SECONDS


# ==============================================================================
# DUPLICATE PACKAGE DETECTION
# ==============================================================================

# Groups of packages that often provide similar/duplicate functionality
SIMILAR_PACKAGE_GROUPS: List[Dict[str, Any]] = [
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
            "@emotion/styled",
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


# ==============================================================================
# AUTH CONSTANTS
# ==============================================================================

# Authentication providers
AUTH_PROVIDER_LOCAL = "local"
AUTH_PROVIDER_OIDC = "oidc"

# Token expiration times
EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 1

# OIDC State TTL in seconds (5 minutes for authorization flow)
OIDC_STATE_TTL_SECONDS = 300

# TOTP (2FA) settings
TOTP_VALID_WINDOW: int = 1  # Accept codes from 1 interval before/after current

# OIDC HTTP client timeout (seconds)
OIDC_HTTP_TIMEOUT_SECONDS: float = 30.0


# ==============================================================================
# WEBHOOK CONSTANTS
# ==============================================================================

# Webhook configuration
# WEBHOOK_TIMEOUT_SECONDS and WEBHOOK_MAX_RETRIES are now in settings.py
WEBHOOK_LIST_LIMIT: int = 100
WEBHOOK_BACKOFF_BASE: int = 2  # Exponential backoff base (2^n seconds)

# Webhook event types
WEBHOOK_EVENT_SCAN_COMPLETED = "scan_completed"
WEBHOOK_EVENT_VULNERABILITY_FOUND = "vulnerability_found"
WEBHOOK_EVENT_ANALYSIS_FAILED = "analysis_failed"

WEBHOOK_VALID_EVENTS = [
    WEBHOOK_EVENT_SCAN_COMPLETED,
    WEBHOOK_EVENT_VULNERABILITY_FOUND,
    WEBHOOK_EVENT_ANALYSIS_FAILED,
]

# Webhook permissions - Use Permissions class from app.core.permissions instead
# from app.core.permissions import Permissions (Permissions.WEBHOOK_CREATE, etc.)

# Webhook HTTP headers
WEBHOOK_HEADER_CONTENT_TYPE = "Content-Type"
WEBHOOK_HEADER_USER_AGENT = "User-Agent"
WEBHOOK_HEADER_EVENT = "X-Webhook-Event"
WEBHOOK_HEADER_TIMESTAMP = "X-Webhook-Timestamp"
WEBHOOK_HEADER_ID = "X-Webhook-ID"
WEBHOOK_HEADER_SIGNATURE = "X-Webhook-Signature"
WEBHOOK_HEADER_TEST = "X-Webhook-Test"
WEBHOOK_USER_AGENT_VALUE = "DependencyControl-Webhook/1.0"

# Webhook URL validation prefixes
WEBHOOK_ALLOWED_URL_PREFIXES = ("https://", "http://localhost", "http://127.0.0.1")


# ==============================================================================
# SCAN STATUS CONSTANTS
# ==============================================================================

SCAN_STATUS_PENDING = "pending"
SCAN_STATUS_PROCESSING = "processing"
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_FAILED = "failed"

SCAN_VALID_STATUSES = [
    SCAN_STATUS_PENDING,
    SCAN_STATUS_PROCESSING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
]


# ==============================================================================
# SBOM SOURCE TYPE CONSTANTS
# ==============================================================================

SOURCE_TYPE_IMAGE = "image"
SOURCE_TYPE_APPLICATION = "application"
SOURCE_TYPE_FILE = "file"
SOURCE_TYPE_DIRECTORY = "directory"
SOURCE_TYPE_FILE_SYSTEM = "file-system"

# Package types that are typically OS/system packages (from container base images)
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

# Package types that are typically application dependencies
APP_PACKAGE_TYPES = frozenset(
    {
        "npm",
        "pypi",
        "maven",
        "gradle",
        "cargo",
        "gem",
        "nuget",
        "golang",
        "go-module",
        "composer",
        "pip",
        "poetry",
        "yarn",
        "pnpm",
        "hex",
        "cocoapods",
        "swift",
        "pub",
        "hackage",
    }
)


# ==============================================================================
# REACHABILITY CONSTANTS
# ==============================================================================

# Analysis levels
REACHABILITY_LEVEL_NONE = "none"
REACHABILITY_LEVEL_IMPORT = "import"
REACHABILITY_LEVEL_SYMBOL = "symbol"

# Confidence scores for reachability analysis
REACHABILITY_CONFIDENCE_NOT_USED = 0.9  # High confidence package is NOT used
REACHABILITY_CONFIDENCE_IMPORTED_NO_SYMBOLS = 0.5  # Package imported, unknown functions
REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO = (
    0.4  # Package imported, no symbol analysis available
)

# Confidence base scores for symbol extraction
REACHABILITY_EXTRACTION_CONFIDENCE = {
    "high": 0.9,
    "medium": 0.7,
    "low": 0.5,
}


# ==============================================================================
# GITLAB ACCESS LEVEL CONSTANTS
# ==============================================================================

GITLAB_ACCESS_GUEST = 10
GITLAB_ACCESS_REPORTER = 20
GITLAB_ACCESS_DEVELOPER = 30
GITLAB_ACCESS_MAINTAINER = 40
GITLAB_ACCESS_OWNER = 50

# Minimum access level for admin role in DependencyControl
GITLAB_ADMIN_MIN_ACCESS = GITLAB_ACCESS_MAINTAINER


# ==============================================================================
# AGGREGATION CONSTANTS
# ==============================================================================

# Aggregation key prefixes for finding deduplication
AGG_KEY_VULNERABILITY = "AGG:VULN"
AGG_KEY_QUALITY = "AGG:QUALITY"
AGG_KEY_SAST = "SAST-AGG"

# Limits for waiver queries
WAIVER_QUERY_LIMIT = 1000

# Waiver status values
WAIVER_STATUS_ACCEPTED_RISK = "accepted_risk"
WAIVER_STATUS_FALSE_POSITIVE = "false_positive"

WAIVER_STATUSES = [
    WAIVER_STATUS_ACCEPTED_RISK,
    WAIVER_STATUS_FALSE_POSITIVE,
]


# ==============================================================================
# CVSS SEVERITY SCORE MAPPING
# ==============================================================================

# Default CVSS scores used when actual score is not available
CVSS_SEVERITY_SCORES: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
    "UNKNOWN": 0.0,
}


# ==============================================================================
# CACHE TTL CONSTANTS
# ==============================================================================

# GitLab JWKS cache TTLs (in seconds)
GITLAB_JWKS_CACHE_TTL = 3600  # 1 hour
GITLAB_JWKS_URI_CACHE_TTL = 86400  # 24 hours (rarely changes)


# ==============================================================================
# HOUSEKEEPING CONSTANTS (Implementation Details - not configurable)
# ==============================================================================

# Time (seconds) since last result to trigger aggregation for stale scans
# This is tuned for typical CI pipeline timing - don't change unless you understand the implications
HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS: int = 30

# Maximum retries for stuck scans before marking as failed
HOUSEKEEPING_MAX_SCAN_RETRIES: int = 3

# Interval (seconds) for checking stale pending scans (fast loop for responsiveness)
HOUSEKEEPING_STALE_SCAN_INTERVAL_SECONDS: int = 10

# Interval (seconds) for main housekeeping loop (stuck scans, re-scans)
HOUSEKEEPING_MAIN_LOOP_INTERVAL_SECONDS: int = 300  # 5 minutes

# Fixed interval for retention cleanup checks (hours)
HOUSEKEEPING_RETENTION_CHECK_INTERVAL_HOURS: int = 24


# ==============================================================================
# RETRY CONSTANTS (Standard values - not configurable)
# ==============================================================================

# Maximum retries for enrichment API calls
ENRICHMENT_MAX_RETRIES: int = 3

# Delay between retries (seconds)
ENRICHMENT_RETRY_DELAY: float = 1.0

# Maximum retries for webhook delivery
WEBHOOK_MAX_RETRIES: int = 3
