import { Finding } from './scan';
import { Severity, SeverityBreakdown } from './common';

export type { Severity, SeverityBreakdown };

export interface DashboardStats {
    total_projects: number;
    total_critical: number;
    total_high: number;
    avg_risk_score: number;
    top_risky_projects: {
        name: string;
        risk: number;
        id: string;
    }[];
}

export interface SearchResult {
  project_id: string;
  project_name: string;
  package: string;
  version: string;
  type: string;
  license?: string;
  direct?: boolean;
  direct_inferred?: boolean;
  purl?: string;
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  locations?: string[];
}

export interface DependencyUsage {
  name: string;
  type: string;
  versions: string[];
  project_count: number;
  total_occurrences: number;
  has_vulnerabilities: boolean;
  vulnerability_count: number;
}

export interface DependencyTreeNode {
  id: string;
  name: string;
  version: string;
  purl: string;
  type: string;
  direct: boolean;
  direct_inferred?: boolean;
  has_findings: boolean;
  findings_count: number;
  findings_severity?: SeverityBreakdown;
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  locations?: string[];
  children: DependencyTreeNode[];
}

export interface ImpactAnalysisResult {
  component: string;
  version: string;
  affected_projects: number;
  total_findings: number;
  findings_by_severity: SeverityBreakdown;
  recommended_version?: string;
  fix_impact_score: number;
  affected_project_names: string[];
  max_epss_score?: number;
  epss_percentile?: number;
  has_kev?: boolean;
  kev_count?: number;
  kev_ransomware_use?: boolean;
  kev_due_date?: string;
  days_until_due?: number; 
  exploit_maturity?: string;
  max_risk_score?: number;
  days_known?: number;
  has_fix?: boolean;
  fix_versions?: string[];
  priority_reasons?: string[];
}

export interface VulnerabilityHotspot {
  component: string;
  version: string;
  type: string;
  finding_count: number;
  severity_breakdown: SeverityBreakdown;
  affected_projects: string[];
  first_seen: string;
  max_epss_score?: number;
  epss_percentile?: number;
  has_kev?: boolean;
  kev_count?: number;
  kev_ransomware_use?: boolean;
  kev_due_date?: string;
  days_until_due?: number;
  exploit_maturity?: string;
  max_risk_score?: number;
  days_known?: number;
  has_fix?: boolean;
  fix_versions?: string[];
  top_cves?: string[];
  priority_reasons?: string[]; 
}

export interface DependencyTypeStats {
  type: string;
  count: number;
  percentage: number;
}

export interface AnalyticsSummary {
  total_dependencies: number;
  total_vulnerabilities: number;
  unique_packages: number;
  dependency_types: DependencyTypeStats[];
  severity_distribution: SeverityBreakdown;
}

export interface AdvancedSearchResult {
  project_id: string;
  project_name: string;
  package: string;
  version: string;
  type: string;
  license?: string;
  license_url?: string;
  direct: boolean;
  direct_inferred?: boolean;
  purl?: string;
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  locations?: string[];
  cpes?: string[];
  description?: string;
  author?: string;
  publisher?: string;
  group?: string;
  homepage?: string;
  repository_url?: string;
  download_url?: string;
  hashes?: Record<string, string>;
  properties?: Record<string, string>;
  found_by?: string;
  license_category?: string; 
  licenses_detailed?: Array<{
    spdx_id: string;
    source: string;
    category?: string;
    explanation?: string;
  }>;
  license_risks?: string[];
  license_obligations?: string[];
  enrichment_sources?: string[];
  deps_dev?: {
    stars?: number;
    forks?: number;
    open_issues?: number;
    project_url?: string;
    project_description?: string;
    project_license?: string;
    dependents?: {
      total?: number;
      direct?: number;
      indirect?: number;
    };
    scorecard?: {
      overall_score?: number;
      date?: string;
      checks_count?: number;
    };
    links?: Record<string, string>;
    published_at?: string;
    is_deprecated?: boolean;
    known_advisories?: string[];
    has_attestations?: boolean;
    has_slsa_provenance?: boolean;
  };
}

export interface HotspotsQueryParams {
  skip?: number;
  limit?: number;
  sort_by?: 'finding_count' | 'component' | 'first_seen' | 'epss' | 'risk';
  sort_order?: 'asc' | 'desc';
}

export interface AdvancedSearchResponse {
  items: AdvancedSearchResult[];
  total: number;
  page: number;
  size: number;
}

export interface VulnerabilitySearchResult {
  vulnerability_id: string;
  aliases: string[];
  severity: Severity;
  cvss_score?: number;
  epss_score?: number;
  epss_percentile?: number;
  in_kev: boolean;
  kev_ransomware: boolean;
  kev_due_date?: string;
  component: string;
  version: string;
  component_type?: string;
  purl?: string;
  project_id: string;
  project_name: string;
  scan_id?: string;
  finding_id: string;
  finding_type: string;
  description?: string;
  fixed_version?: string;
  waived: boolean;
  waiver_reason?: string;
}

export interface VulnerabilitySearchResponse {
  items: VulnerabilitySearchResult[];
  total: number;
  page: number;
  size: number;
}

export interface VulnerabilitySearchOptions {
  severity?: string;
  in_kev?: boolean;
  has_fix?: boolean;
  finding_type?: string;
  project_ids?: string[];
  include_waived?: boolean;
  sort_by?: 'severity' | 'cvss' | 'epss' | 'component' | 'project_name';
  sort_order?: 'asc' | 'desc';
  skip?: number;
  limit?: number;
}

export type ComponentFinding = Finding & { project_id: string; project_name: string; scan_id?: string };

export interface DependencyMetadata {
  name: string;
  version: string;
  type: string;
  purl?: string;
  description?: string;
  author?: string;
  publisher?: string;
  homepage?: string;
  repository_url?: string;
  download_url?: string;
  group?: string;
  license?: string;
  license_url?: string;
  license_category?: string;
  license_risks?: string[];
  license_obligations?: string[];
  deps_dev?: {
    stars?: number;
    forks?: number;
    open_issues?: number;
    is_deprecated?: boolean;
    known_advisories?: string[];
    published_at?: string;
    project_description?: string;
    project_url?: string;
    dependents?: { total?: number };
    scorecard?: {
      overall_score?: number;
      checks_count?: number;
      date?: string;
    };
    links?: Record<string, string>;
  };
  project_count: number;
  affected_projects: Array<{ id: string; name: string; direct: boolean; direct_inferred?: boolean }>;
  total_vulnerability_count: number;
  total_finding_count: number;
  enrichment_sources?: string[];
}

export type RecommendationType = 
  | 'base_image_update'
  | 'direct_dependency_update'
  | 'transitive_fix_via_parent'
  | 'no_fix_available'
  | 'consider_waiver'
  | 'rotate_secrets'
  | 'remove_secrets'
  | 'fix_code_security'
  | 'fix_infrastructure'
  | 'license_compliance'
  | 'supply_chain_risk'
  | 'outdated_dependency'
  | 'version_fragmentation'
  | 'dev_in_production'
  | 'unmaintained_package'
  | 'recurring_vulnerability'
  | 'regression_detected'
  | 'deep_dependency_chain'
  | 'duplicate_functionality'
  | 'cross_project_pattern'
  | 'shared_vulnerability';

export type RecommendationPriority = 'critical' | 'high' | 'medium' | 'low';

export interface RecommendationImpact {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface CrossProjectCve {
  cve: string;
  total_affected: number;
  affected_projects?: string[];
}

export interface RecommendationAction {
  type: string;
  package?: string;
  current_version?: string;
  target_version?: string;
  current_image?: string;
  suggestion?: string;
  commands?: string[];
  cves?: Array<string | CrossProjectCve>;
  options?: string[];
  suggestions?: string[];
  file_path?: string;
  line_number?: number;
  secret_type?: string;
  files?: string[];
  rule_ids?: string[];
  license_type?: string;
  components?: string[];
  resource_type?: string;
  description?: string;
  packages?: Array<{
    name: string;
    current?: string;
    recommended_major?: number;
    reason?: string;
    versions?: string[];
    suggestion?: string;
    version_count?: number;
    project_count?: number;
  }>;
  new_critical_cves?: string[];
  delta?: number;
  deepest_chains?: Array<{
    package: string;
    depth: number;
    chain_preview?: string;
  }>;
  duplicates?: Array<{
    category: string;
    found: string[];
    suggestion: string;
  }>;
  affected_projects?: string[];
  total_affected?: number;
  priority_projects?: Array<{
    name: string;
    id: string;
    critical: number;
    high: number;
  }>;
}

export interface Recommendation {
  type: RecommendationType;
  priority: RecommendationPriority;
  title: string;
  description: string;
  impact: RecommendationImpact;
  affected_components: string[];
  affected_projects?: Array<{ id: string; name: string }>;
  action: RecommendationAction;
  effort: 'low' | 'medium' | 'high';
}

export interface RecommendationsSummary {
  base_image_updates: number;
  direct_updates: number;
  transitive_updates: number;
  no_fix: number;
  total_fixable_vulns: number;
  total_unfixable_vulns: number;
  secrets_to_rotate: number;
  sast_issues: number;
  iac_issues: number;
  license_issues: number;
  quality_issues: number;
  outdated_deps?: number;
  fragmentation_issues?: number;
  trend_alerts?: number;
  cross_project_issues?: number;
}

export interface RecommendationsResponse {
  project_id: string;
  project_name: string;
  scan_id: string;
  total_findings: number;
  total_vulnerabilities: number;
  recommendations: Recommendation[];
  summary: RecommendationsSummary;
}

export interface AdvancedSearchOptions {
    version?: string;
    type?: string;
    source_type?: string;
    has_vulnerabilities?: boolean;
    project_ids?: string[];
    sort_by?: string;
    sort_order?: 'asc' | 'desc';
    skip?: number;
    limit?: number;
}
