import { Severity } from './common';

export type { Severity };

export interface PipelineMetadata {
  CI_COMMIT_BRANCH?: string;
  CI_DEFAULT_BRANCH?: string;
  CI_PROJECT_PATH?: string;
  CI_PROJECT_ID?: number;
  CI_PIPELINE_ID: number;
  CI_PIPELINE_IID?: number;
  CI_PROJECT_TITLE?: string;
  CI_COMMIT_MESSAGE?: string;
  CI_PROJECT_URL?: string;
  CI_COMMIT_TAG?: string;
  CI_JOB_STARTED_AT?: string;
  CI_JOB_ID?: number;
  CI_PROJECT_NAME?: string;
}

export type FindingType = 
  | "vulnerability"
  | "license"
  | "secret"
  | "malware"
  | "eol"
  | "iac"
  | "sast"
  | "system_warning"
  | "outdated"
  | "quality"
  | "other";

export interface AnalyzerResultData {
  status?: string;
  findings?: unknown[];
  summary?: Record<string, string | number | boolean>;
  metadata?: Record<string, string | number | boolean | null>;
  raw_output?: string;
  [key: string]: string | number | boolean | null | undefined | unknown[] | Record<string, unknown>;
}

export interface ScanAnalysisResult {
  _id: string;
  analyzer_name: string;
  result: AnalyzerResultData;
  created_at?: string;
  scan_id?: string;
}

export interface ReachabilityInfo {
  is_reachable?: boolean;
  analysis_level?: string;
  confidence_score?: number;
  call_path?: string[];
  matched_symbols?: string[];
}

export interface NestedVulnerability {
  id?: string;
  severity?: Severity;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  epss_percentile?: number;
  epss_date?: string;
  description?: string;
  fixed_version?: string;
  resolved_cve?: string;
  github_advisory_url?: string;
  kev?: boolean;
  kev_ransomware?: boolean;
  kev_due_date?: string;
  waived?: boolean;
  waiver_reason?: string;
  urls?: string[];
  references?: string[];
  aliases?: string[];
  scanners?: string[];
  exploit_maturity?: string;
  details?: {
    published_date?: string;
    last_modified_date?: string;
    cwe_ids?: string[];
    [key: string]: string | string[] | number | boolean | null | undefined;
  };
  in_kev?: boolean;
  kev_ransomware_use?: string;
  kev_date_added?: string;
  kev_required_action?: string;
  reachability?: ReachabilityInfo;
}

export interface QualityIssueDetails {
  check_name?: string;
  check_score?: number;
  reason?: string;
  documentation_url?: string;
  [key: string]: string | number | boolean | undefined;
}

export interface QualityIssue {
  id: string;
  type?: string;
  severity?: string;
  description?: string;
  scanners?: string[];
  source?: string;
  details?: QualityIssueDetails;
}

export interface VulnerabilityInfoSummary {
  has_vulnerabilities?: boolean;
  vuln_count?: number;
  critical_count?: number;
  high_count?: number;
  vulnerability_finding_id?: string;
  vulnerabilities?: NestedVulnerability[];
}

export interface OutdatedInfoSummary {
  is_outdated?: boolean;
  current_version?: string;
  latest_version?: string;
  message?: string;
  outdated_finding_id?: string;
}

export interface QualityInfoSummary {
  has_quality_issues?: boolean;
  issue_count?: number;
  overall_score?: number;
  has_maintenance_issues?: boolean;
  quality_finding_id?: string;
  quality_issues?: QualityIssue[];
}

export interface LicenseInfoSummary {
  has_license_issue?: boolean;
  license?: string;
  category?: string;
  license_finding_id?: string;
}

export interface EolInfoSummary {
  is_eol?: boolean;
  eol_date?: string;
  cycle?: string;
  latest_version?: string;
  eol_finding_id?: string;
}

export interface ScorecardContext {
  overall_score?: number;
  maintenance_risk?: boolean;
  has_vulnerabilities_issue?: boolean;
  critical_issues?: string[];
  project_url?: string;
}

export interface FindingMetadata {
  scanner_version?: string;
  scan_timestamp?: string;
  source_file?: string;
  source_line?: number;
  category?: string;
  tags?: string[];
  [key: string]: string | number | boolean | string[] | undefined;
}

export interface ScorecardData {
  overall_score?: number;
  checks?: Array<{
    name: string;
    score: number;
    reason?: string;
  }>;
  date?: string;
  repository_url?: string;
  [key: string]: string | number | boolean | null | undefined | Array<{ name: string; score: number; reason?: string }>;
}

export interface MaintainerRiskData {
  risk_level?: 'low' | 'medium' | 'high' | 'critical';
  factors?: string[];
  last_commit_date?: string;
  maintainer_count?: number;
  is_abandoned?: boolean;
  [key: string]: string | string[] | number | boolean | null | undefined;
}

export interface ErrorDetails {
  code?: string;
  message?: string;
  stack?: string;
  [key: string]: string | number | boolean | undefined;
}

export interface FindingDetails {
  vulnerabilities?: NestedVulnerability[];
  quality_issues?: QualityIssue[];
  reachability?: ReachabilityInfo;
  vulnerability_info?: VulnerabilityInfoSummary;
  outdated_info?: OutdatedInfoSummary;
  quality_info?: QualityInfoSummary;
  license_info?: LicenseInfoSummary;
  eol_info?: EolInfoSummary;
  scorecard_context?: ScorecardContext;
  additional_finding_types?: Array<{ type: string; severity: string }>;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  epss_percentile?: number;
  epss_date?: string;
  fixed_version?: string;
  github_advisory_url?: string;
  kev?: boolean;
  kev_ransomware?: boolean;
  kev_due_date?: string;
  urls?: string[];
  references?: string[];
  in_kev?: boolean;
  kev_ransomware_use?: string;
  kev_date_added?: string;
  kev_required_action?: string;
  exploit_maturity?: string;
  detector?: string;
  decoder?: string;
  verified?: boolean;
  redacted?: string;
  line?: number;
  file?: string;
  rule_id?: string;
  check_id?: string;
  start?: { line?: number; column?: number };
  end?: { line?: number; column?: number };
  metadata?: FindingMetadata;
  cwe_ids?: string[];
  published_date?: string;
  last_modified_date?: string;
  title?: string;
  documentation_url?: string;
  category_groups?: string[];
  code_extract?: string;
  fingerprint?: string;
  parent_line?: number;
  sink_content?: string;
  owasp?: string[];
  source_rule_url?: string;
  confidence?: string;
  likelihood?: string;
  impact?: string;
  technology?: string[];
  subcategory?: string[];
  vulnerability_class?: string[];
  platform?: string;
  issue_type?: string;
  expected_value?: string;
  actual_value?: string;
  license?: string;
  license_url?: string;
  category?: string;
  explanation?: string;
  recommendation?: string;
  obligations?: string[];
  license_risks?: string[];
  overall_score?: number;
  has_maintenance_issues?: boolean;
  issue_count?: number;
  failed_checks?: Array<{ name: string; score: number }>;
  critical_issues?: string[];
  repository?: string;
  checks_summary?: Record<string, number>;
  risks?: Array<{
    type: string;
    severity: string;
    description: string;
    severity_score?: number;
    message?: string;
    detail?: string;
  }>;
  maintainer_info?: {
    name?: string;
    email?: string;
    packages_maintained?: number;
  };
  maintenance_warning?: boolean;
  maintenance_warning_text?: string;
  scorecard?: ScorecardData;
  maintainer_risk?: MaintainerRiskData;
  error_details?: string | ErrorDetails;
}

export interface Finding {
  id: string;
  type: FindingType;
  severity: Severity;
  component: string;
  version?: string;
  description: string;
  scanners: string[];
  details: FindingDetails;
  found_in: string[];
  aliases: string[];
  related_findings?: string[];
  waived: boolean;
  waiver_reason?: string;
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  found_by?: string;
  locations?: string[];
  purl?: string;
  direct?: boolean;
  direct_inferred?: boolean;
}

export interface ThreatIntelligenceStats {
  kev_count: number;
  kev_ransomware_count: number;
  high_epss_count: number;
  medium_epss_count: number;
  avg_epss_score: number | null;
  max_epss_score: number | null;
  weaponized_count: number;
  active_exploitation_count: number;
  exploitable_count?: number;
  total_enriched?: number;
}

export interface ReachabilityStats {
  analyzed_count: number;
  reachable_count: number;
  likely_reachable_count: number;
  unreachable_count: number;
  unknown_count: number;
  reachable_critical: number;
  reachable_high: number;
  reachable?: number;
  potentially_reachable?: number;
  total_analyzed?: number;
}

export interface PrioritizedCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  actionable_critical: number;
  actionable_high: number;
  actionable_total: number;
  deprioritized_count: number;
}

export interface SbomData {
  format?: string;
  version?: string;
  source?: string;
  component_count?: number;
  components?: Array<{
    name: string;
    version?: string;
    type?: string;
    purl?: string;
  }>;
  [key: string]: string | number | boolean | null | undefined | Array<{ name: string; version?: string; type?: string; purl?: string }>;
}

export interface EnhancedStats {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  unknown?: number;
  risk_score?: number;
  adjusted_risk_score?: number;
  threat_intel?: ThreatIntelligenceStats | null;
  reachability?: ReachabilityStats | null;
  prioritized?: PrioritizedCounts | null;
}

export interface Scan {
  _id: string;
  project_id: string;
  branch: string;
  commit_hash?: string;
  pipeline_id?: number;
  pipeline_iid?: number;
  metadata?: PipelineMetadata;
  project_url?: string;
  pipeline_url?: string;
  project_name?: string;
  commit_message?: string;
  commit_tag?: string;
  pipeline_user?: string;
  created_at: string;
  status: string;
  findings_summary?: Finding[];
  findings_count?: number;
  ignored_count?: number;
  stats?: EnhancedStats | null;
  completed_at?: string;
  sbom?: SbomData;
  sboms?: SbomData[];
  sbom_refs?: string[];
  is_rescan?: boolean;
  original_scan_id?: string;
  latest_rescan_id?: string;
  job_started_at?: string;
  latest_run?: {
    scan_id: string;
    status: string;
    findings_count: number;
    stats: EnhancedStats | null;
    completed_at?: string;
    created_at?: string;
  };
}