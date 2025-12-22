export const PERMISSION_GROUPS = [
  {
    title: "System & Administration",
    permissions: [
      { id: "*", label: "Administrator", description: "Full access to all resources" },
      { id: "system:manage", label: "System Settings", description: "Manage system configurations" },
    ]
  },
  {
    title: "User Management",
    permissions: [
      { id: "user:read_all", label: "List All Users", description: "View list of all users in the system" },
      { id: "user:create", label: "Create Users", description: "Create new users" },
      { id: "user:read", label: "Read User Details", description: "View detailed user information" },
      { id: "user:update", label: "Update Users", description: "Update user profiles" },
      { id: "user:delete", label: "Delete Users", description: "Delete users" },
    ]
  },
  {
    title: "Team Management",
    permissions: [
      { id: "team:read_all", label: "Read All Teams", description: "View all teams in the system" },
      { id: "team:read", label: "Read Own Teams", description: "View teams you are a member of" },
      { id: "team:create", label: "Create Teams", description: "Create new teams" },
      { id: "team:update", label: "Update Teams", description: "Update any team" },
      { id: "team:delete", label: "Delete Teams", description: "Delete any team" },
    ]
  },
  {
    title: "Project Management",
    permissions: [
      { id: "project:read_all", label: "Read All Projects", description: "View all projects in the system" },
      { id: "project:read", label: "Read Own Projects", description: "View projects you are a member of" },
      { id: "project:create", label: "Create Projects", description: "Create new projects" },
      { id: "project:update", label: "Update Projects", description: "Update any project" },
      { id: "project:delete", label: "Delete Projects", description: "Delete any project" },
    ]
  },
  {
    title: "Analytics & Insights",
    permissions: [
      { id: "analytics:read", label: "View Analytics", description: "Access the Analytics dashboard and view statistics" },
      { id: "analytics:summary", label: "View Summary", description: "View analytics summary and overview data" },
      { id: "analytics:dependencies", label: "View Dependencies", description: "View cross-project dependency analysis" },
      { id: "analytics:tree", label: "View Dependency Tree", description: "View dependency tree visualization" },
      { id: "analytics:impact", label: "View Impact Analysis", description: "View impact analysis and fix recommendations" },
      { id: "analytics:hotspots", label: "View Hotspots", description: "View vulnerability hotspots across projects" },
      { id: "analytics:search", label: "Cross-Project Search", description: "Search dependencies across all accessible projects" },
    ]
  },
  {
    title: "Security & Compliance",
    permissions: [
      { id: "waiver:read_all", label: "Read All Waivers", description: "View all waivers in the system" },
      { id: "waiver:read", label: "Read Own Waivers", description: "View waivers for your projects" },
      { id: "waiver:manage", label: "Manage Waivers", description: "Create global waivers" },
      { id: "waiver:delete", label: "Delete Waivers", description: "Delete any waiver" },
    ]
  },
  {
    title: "Integrations",
    permissions: [
      { id: "webhook:create", label: "Create Webhooks", description: "Create webhooks for any project" },
      { id: "webhook:delete", label: "Delete Webhooks", description: "Delete any webhook" },
    ]
  }
];

export const AVAILABLE_ANALYZERS = [
  { id: 'end_of_life', label: 'End of Life (EOL)', description: 'Checks if packages have reached their End-of-Life date and are no longer supported.' },
  { id: 'os_malware', label: 'Open Source Malware', description: 'Checks packages against the Open Source Malware database for known malicious packages.' },
  { id: 'trivy', label: 'Trivy (Container/FS)', description: 'Scans container images and filesystems for vulnerabilities (CVEs) and misconfigurations.' },
  { id: 'osv', label: 'OSV (Open Source Vulnerabilities)', description: 'Checks dependencies against the Open Source Vulnerabilities (OSV) database.' },
  { id: 'deps_dev', label: 'Deps.dev (Google)', description: 'Queries Google\'s deps.dev API for security, license, and maintenance information.' },
  { id: 'license_compliance', label: 'License Compliance', description: 'Analyzes package licenses to ensure compliance with project policies.' },
  { id: 'grype', label: 'Grype (Anchore)', description: 'A vulnerability scanner for container images and filesystems, similar to Trivy.' },
  { id: 'outdated_packages', label: 'Outdated Packages', description: 'Identifies packages that are not on the latest version.' },
  { id: 'typosquatting', label: 'Typosquatting', description: 'Detects potential typosquatting attacks (packages with names similar to popular ones).' },
  { id: 'opengrep', label: 'OpenGrep (SAST)', description: 'Static Application Security Testing (SAST) tool to find security flaws in code.' },
  { id: 'kics', label: 'KICS (IaC)', description: 'Finds security vulnerabilities, compliance issues, and infrastructure misconfigurations in IaC.' },
  { id: 'bearer', label: 'Bearer (SAST/Data)', description: 'Static Application Security Testing (SAST) and Data Security tool.' },
  { id: 'trufflehog', label: 'TruffleHog (Secrets)', description: 'Scans for hardcoded secrets, passwords, and keys in the codebase.' },
];

// Pagination & Query Limits
export const DEFAULT_PAGE_SIZE = 50;
export const LARGE_PAGE_SIZE = 100;
export const MAX_SCANS_FOR_CHARTS = 100;
export const DEBOUNCE_DELAY_MS = 300;
export const VIRTUAL_SCROLL_OVERSCAN = 20;
