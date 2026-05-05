// Re-export from permissions.ts for legacy import paths.
export {
  PERMISSION_GROUPS,
  Permissions,
  ALL_PERMISSIONS,
  PRESET_ADMIN,
  PRESET_USER,
  PRESET_VIEWER,
  hasPermission,
} from './permissions';

import { Permissions } from './permissions';

export const AVAILABLE_ANALYZERS = [
  { id: 'trivy', label: 'Trivy (Container/FS)', description: 'Scans container images and filesystems for vulnerabilities (CVEs) and misconfigurations.', category: 'vulnerability' },
  { id: 'grype', label: 'Grype (Anchore)', description: 'A vulnerability scanner for container images and filesystems, similar to Trivy.', category: 'vulnerability' },
  { id: 'osv', label: 'OSV (Open Source Vulnerabilities)', description: 'Checks dependencies against the Open Source Vulnerabilities (OSV) database.', category: 'vulnerability' },
  { id: 'deps_dev', label: 'Deps.dev (Google)', description: 'Queries Google\'s deps.dev API for security, license, and maintenance information.', category: 'vulnerability' },
  { id: 'epss_kev', label: 'EPSS/KEV Enrichment', description: 'Enriches vulnerabilities with EPSS exploitation probability and CISA Known Exploited Vulnerabilities (KEV) data. Requires vulnerability scanners (Trivy, Grype, OSV) to find CVEs first.', category: 'enrichment', isPostProcessor: true, dependsOn: ['trivy', 'grype', 'osv', 'deps_dev'] },
  { id: 'reachability', label: 'Reachability Analysis', description: 'Analyzes if vulnerable code paths are reachable from your application. Requires vulnerability findings and a callgraph uploaded via CI/CD.', category: 'enrichment', isPostProcessor: true, dependsOn: ['trivy', 'grype', 'osv', 'deps_dev'], requiresCallgraph: true },
  { id: 'end_of_life', label: 'End of Life (EOL)', description: 'Checks if packages have reached their End-of-Life date and are no longer supported.', category: 'compliance' },
  { id: 'license_compliance', label: 'License Compliance', description: 'Analyzes package licenses to ensure compliance with project policies.', category: 'compliance' },
  { id: 'os_malware', label: 'Open Source Malware', description: 'Checks packages against the Open Source Malware database for known malicious packages.', category: 'security' },
  { id: 'typosquatting', label: 'Typosquatting', description: 'Detects potential typosquatting attacks (packages with names similar to popular ones).', category: 'security' },
  { id: 'hash_verification', label: 'Hash Verification', description: 'Verifies package integrity by comparing checksums against official registry hashes (PyPI, npm).', category: 'security' },
  { id: 'maintainer_risk', label: 'Maintainer Risk', description: 'Assesses supply chain risks: stale packages, single maintainers, archived repos, and more.', category: 'quality' },
  { id: 'outdated_packages', label: 'Outdated Packages', description: 'Identifies packages that are not on the latest version.', category: 'quality' },
  { id: 'opengrep', label: 'OpenGrep (SAST)', description: 'Static Application Security Testing (SAST) tool to find security flaws in code.', category: 'sast' },
  { id: 'kics', label: 'KICS (IaC)', description: 'Finds security vulnerabilities, compliance issues, and infrastructure misconfigurations in IaC.', category: 'sast' },
  { id: 'bearer', label: 'Bearer (SAST/Data)', description: 'Static Application Security Testing (SAST) and Data Security tool.', category: 'sast' },
  { id: 'trufflehog', label: 'TruffleHog (Secrets)', description: 'Scans for hardcoded secrets, passwords, and keys in the codebase.', category: 'secrets' },
];

export const ANALYZER_CATEGORIES = {
  vulnerability: { label: 'Vulnerability Scanners', description: 'Detect known vulnerabilities (CVEs) in dependencies', icon: 'shield-alert' },
  enrichment: { label: 'Vulnerability Enrichment', description: 'Enrich vulnerability findings with additional context (runs after vulnerability scanners)', icon: 'sparkles' },
  compliance: { label: 'Compliance & Lifecycle', description: 'Check license compliance and package lifecycle status', icon: 'scale' },
  security: { label: 'Supply Chain Security', description: 'Detect malicious packages and supply chain attacks', icon: 'shield-check' },
  quality: { label: 'Code Quality', description: 'Assess package maintenance and update status', icon: 'bar-chart' },
  sast: { label: 'SAST (Code Analysis)', description: 'Static analysis of source code for security flaws', icon: 'code' },
  secrets: { label: 'Secret Scanning', description: 'Detect exposed credentials and secrets', icon: 'key' },
};

export const TEAM_ROLES = [
  { value: 'member', label: 'Member' },
  { value: 'admin', label: 'Admin' },
] as const;

export const DEFAULT_PAGE_SIZE = 50;
export const SMALL_PAGE_SIZE = 20;
export const PROJECT_GRID_PAGE_SIZE = 12;
export const DROPDOWN_PAGE_SIZE = 100;
export const MAX_SCANS_FOR_CHARTS = 100;
export const VIRTUAL_SCROLL_OVERSCAN = 20;

export const DEBOUNCE_DELAY_MS = 300;
export const COPY_FEEDBACK_DELAY_MS = 2000;
export const API_TIMEOUT_MS = 30000;
export const API_REFRESH_TIMEOUT_MS = 10000;

export const QUERY_STALE_TIMES = {
  FAST: 2 * 60 * 1000,       // 2 min - frequently changing data (dashboard stats)
  STANDARD: 5 * 60 * 1000,   // 5 min - most data
  SLOW: 30 * 60 * 1000,      // 30 min - rarely changing data (dependency types, configs)
} as const;

export const ANALYTICS_PERMISSIONS = [
  Permissions.ANALYTICS_READ,
  Permissions.ANALYTICS_SUMMARY,
  Permissions.ANALYTICS_DEPENDENCIES,
  Permissions.ANALYTICS_TREE,
  Permissions.ANALYTICS_IMPACT,
  Permissions.ANALYTICS_HOTSPOTS,
  Permissions.ANALYTICS_SEARCH,
] as const;

export const POST_PROCESSOR_ANALYZERS = ['epss_kev', 'reachability'] as const;

// Per-user notification events. Must match `NOTIFICATION_EVENTS` in
// backend/app/core/constants.py.
export const NOTIFICATION_EVENTS = [
  {
    id: 'analysis_completed',
    label: 'Analysis Completed',
    description: 'When a dependency scan finishes.',
  },
  {
    id: 'analysis_failed',
    label: 'Analysis Failed',
    description: 'When a scan errors out and could not complete.',
  },
  {
    id: 'vulnerability_found',
    label: 'Vulnerability Found',
    description: 'When critical/high vulnerabilities or KEV entries are detected.',
  },
  {
    id: 'sbom_ingested',
    label: 'SBOM Ingested',
    description: 'When new SBOM data is uploaded for the project (can be noisy in CI).',
  },
  {
    id: 'crypto_asset_ingested',
    label: 'Crypto Asset Ingested',
    description: 'When new CBOM/crypto asset data is uploaded for the project.',
  },
  {
    id: 'crypto_policy_changed',
    label: 'Crypto Policy Changed',
    description: 'When the project\'s cryptography policy is updated.',
  },
  {
    id: 'license_policy_changed',
    label: 'License Policy Changed',
    description: 'When the project\'s license policy is updated.',
  },
  {
    id: 'compliance_report_generated',
    label: 'Compliance Report Generated',
    description: 'When a new compliance report is rendered for the project.',
  },
  {
    id: 'pqc_migration_plan_generated',
    label: 'PQC Migration Plan Generated',
    description: 'When a new post-quantum migration plan is generated for the project.',
  },
] as const;

export const NOTIFICATION_CHANNELS = [
  { id: 'email', label: 'Email' },
  { id: 'slack', label: 'Slack' },
  { id: 'mattermost', label: 'Mattermost' },
] as const;
