import axios, { AxiosError } from 'axios';
import { logger } from './logger';

// Standard API error response shape
export interface ApiErrorData {
  detail?: string;
  message?: string;
}

// Type-safe API error
export type ApiError = AxiosError<ApiErrorData>;

// Define the shape of the runtime config
interface RuntimeConfig {
  VITE_API_URL?: string;
}

// Extend the window interface
declare global {
  interface Window {
    __RUNTIME_CONFIG__?: RuntimeConfig;
  }
}

const getBaseUrl = () => {
  if (window.__RUNTIME_CONFIG__?.VITE_API_URL) {
    return window.__RUNTIME_CONFIG__.VITE_API_URL;
  }
  return import.meta.env.VITE_API_URL || '/api/v1';
};

const api = axios.create({
  baseURL: getBaseUrl(),
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  logger.debug(`Request: ${config.method?.toUpperCase()} ${config.url}`);
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  logger.error('Request Error:', error);
  return Promise.reject(error);
});

export interface Token {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export const login = async (username: string, password: string, otp?: string) => {
  const params = new URLSearchParams();
  params.append('username', username);
  params.append('password', password);
  params.append('grant_type', 'password');
  if (otp) {
    params.append('otp', otp);
  }

  const response = await api.post<Token>('/login/access-token', params, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  return response.data;
};

export const refreshToken = async (token: string) => {
    const response = await api.post<Token>('/login/refresh-token', { refresh_token: token });
    return response.data;
}

export interface PublicConfig {
  allow_public_registration: boolean;
  enforce_2fa: boolean;
  enforce_email_verification: boolean;
  oidc_enabled?: boolean;
  oidc_provider_name?: string;
}

export const getPublicConfig = async () => {
  const response = await api.get<PublicConfig>('/system/public-config');
  return response.data;
};

export const getNotificationChannels = async () => {
  const response = await api.get<string[]>('/system/notifications/channels');
  return response.data;
};

export const signup = async (username: string, email: string, password: string) => {
  const response = await api.post<User>('/signup', { username, email, password });
  return response.data;
};

export const verifyEmail = async (token: string) => {
  const response = await api.get<{ message: string }>(`/verify-email?token=${token}`);
  return response.data;
};

export const resendVerificationEmail = async (email: string) => {
  const response = await api.post<{ message: string }>('/resend-verification', { email });
  return response.data;
};

export interface User {
  id: string;
  _id?: string;
  email: string;
  username: string;
  is_active: boolean;
  is_verified?: boolean;
  auth_provider?: string;
  permissions: string[];
  totp_enabled: boolean;
  slack_username?: string;
  mattermost_username?: string;
  notification_preferences?: Record<string, string[]>;
  status?: 'active' | 'invited';
}

export interface SystemInvitation {
  _id: string;
  email: string;
  token: string;
  invited_by: string;
  created_at: string;
  expires_at: string;
  is_used: boolean;
}

export const getPendingInvitations = async () => {
  const response = await api.get<SystemInvitation[]>('/invitations/system');
  return response.data;
};

export const getMe = async () => {
  const response = await api.get<User>('/users/me');
  return response.data;
};

export interface ProjectMember {
  user_id: string;
  username?: string;
  role: string;
  notification_preferences?: Record<string, string[]>;
  inherited_from?: string;
}

// Extended Stats Types for EPSS/KEV/Reachability
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

export interface Project {
  _id: string;
  name: string;
  owner_id: string;
  team_id?: string;
  members?: ProjectMember[];
  active_analyzers?: string[];
  retention_days?: number;
  default_branch?: string;
  enforce_notification_settings?: boolean;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  gitlab_project_id?: number;
  owner_notification_preferences?: {
    [key: string]: string[];
  };
  stats?: EnhancedStats | null;
  last_scan_at?: string;
}

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

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE" | "INFO" | "UNKNOWN";

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

// Nested vulnerability within a Finding's details
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
    [key: string]: unknown;
  };
  // Additional KEV fields
  in_kev?: boolean;
  kev_ransomware_use?: string;
  kev_date_added?: string;
  kev_required_action?: string;
  // Reachability
  reachability?: ReachabilityInfo;
}

// Reachability information within finding details
export interface ReachabilityInfo {
  is_reachable?: boolean;
  analysis_level?: string;
  confidence_score?: number;
  call_path?: string[];
  matched_symbols?: string[];
}

// Quality issue within finding details
export interface QualityIssue {
  id: string;
  type?: string;
  severity?: string;
  description?: string;
  scanners?: string[];
  source?: string;
  details?: Record<string, unknown>;
}

// Vulnerability info summary (when primary finding is not vulnerability)
export interface VulnerabilityInfoSummary {
  has_vulnerabilities?: boolean;
  vuln_count?: number;
  critical_count?: number;
  high_count?: number;
  vulnerability_finding_id?: string;
  vulnerabilities?: NestedVulnerability[];
}

// Outdated info summary
export interface OutdatedInfoSummary {
  is_outdated?: boolean;
  current_version?: string;
  latest_version?: string;
  message?: string;
  outdated_finding_id?: string;
}

// Quality info summary
export interface QualityInfoSummary {
  has_quality_issues?: boolean;
  issue_count?: number;
  overall_score?: number;
  has_maintenance_issues?: boolean;
  quality_finding_id?: string;
  quality_issues?: QualityIssue[];
}

// License info summary
export interface LicenseInfoSummary {
  has_license_issue?: boolean;
  license?: string;
  category?: string;
  license_finding_id?: string;
}

// EOL info summary
export interface EolInfoSummary {
  is_eol?: boolean;
  eol_date?: string;
  cycle?: string;
  latest_version?: string;
  eol_finding_id?: string;
}

// Scorecard context
export interface ScorecardContext {
  overall_score?: number;
  maintenance_risk?: boolean;
  has_vulnerabilities_issue?: boolean;
  critical_issues?: string[];
  project_url?: string;
}

// Secret details
export interface SecretDetails {
  detector?: string;
  decoder?: string;
  verified?: boolean;
  redacted?: string;
  line?: number;
}

// Type-safe Finding details
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
  // Additional KEV fields at finding level
  in_kev?: boolean;
  kev_ransomware_use?: string;
  kev_date_added?: string;
  kev_required_action?: string;
  // Exploit maturity
  exploit_maturity?: string;
  // Secret fields
  detector?: string;
  decoder?: string;
  verified?: boolean;
  redacted?: string;
  line?: number;
  // SAST/IaC fields
  file?: string;
  rule_id?: string;
  check_id?: string;
  start?: { line?: number; column?: number };
  end?: { line?: number; column?: number };
  metadata?: Record<string, unknown>;
  cwe_ids?: string[];
  published_date?: string;
  last_modified_date?: string;
  // License fields
  license?: string;
  license_url?: string;
  category?: string;
  explanation?: string;
  recommendation?: string;
  obligations?: string[];
  license_risks?: string[];  // string array for license-specific risks
  // Quality fields
  overall_score?: number;
  has_maintenance_issues?: boolean;
  issue_count?: number;
  failed_checks?: Array<{ name: string; score: number }>;
  critical_issues?: string[];
  repository?: string;
  checks_summary?: Record<string, number>;
  // Maintainer risk fields
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
  // Legacy quality/scorecard fields
  maintenance_warning?: boolean;
  maintenance_warning_text?: string;
  scorecard?: Record<string, unknown>;
  maintainer_risk?: Record<string, unknown>;
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
  // Source information (from dependency lookup)
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  found_by?: string;
  locations?: string[];
  purl?: string;
  direct?: boolean;
}

export interface AnalysisResult {
  _id: string;
  scan_id: string;
  analyzer_name: string;
  result: Record<string, unknown>;
  created_at: string;
}

export const getScanResults = async (scanId: string) => {
  const response = await api.get<AnalysisResult[]>(`/projects/scans/${scanId}/results`);
  return response.data;
};

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
  sbom?: Record<string, unknown>;
  sboms?: Record<string, unknown>[];
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

export interface RecentScan extends Scan {
  project_name: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export const getProjects = async (search?: string, skip: number = 0, limit: number = 20, sortBy: string = 'created_at', sortOrder: 'asc' | 'desc' = 'desc') => {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  params.append('skip', skip.toString());
  params.append('limit', limit.toString());
  params.append('sort_by', sortBy);
  params.append('sort_order', sortOrder);
  const response = await api.get<PaginatedResponse<Project>>('/projects/', { params });
  return response.data;
};

export interface ProjectCreate {
  name: string;
  team_id?: string;
  active_analyzers?: string[];
  retention_days?: number;
}

export const createProject = async (data: ProjectCreate) => {
  const response = await api.post<ProjectApiKeyResponse>('/projects/', data);
  return response.data;
};

export interface ProjectUpdate {
  name?: string;
  team_id?: string | null;
  active_analyzers?: string[];
  retention_days?: number;
  enforce_notification_settings?: boolean;
  default_branch?: string | null;
  rescan_enabled?: boolean;
  rescan_interval?: number;
  gitlab_mr_comments_enabled?: boolean;
  owner_notification_preferences?: Record<string, string[]>;
}

export interface ProjectApiKeyResponse {
  project_id: string;
  api_key: string;
  note: string;
}

export const updateProject = async (id: string, data: ProjectUpdate) => {
  const response = await api.put<Project>(`/projects/${id}`, data);
  return response.data;
};

export const deleteProject = async (projectId: string) => {
  await api.delete(`/projects/${projectId}`);
};

export const rotateProjectApiKey = async (id: string) => {
  const response = await api.post<ProjectApiKeyResponse>(`/projects/${id}/rotate-key`);
  return response.data;
};

export interface ProjectNotificationSettings {
  enforce_notification_settings?: boolean;
  notification_preferences: Record<string, string[]>;
}

export const updateProjectNotificationSettings = async (projectId: string, settings: ProjectNotificationSettings) => {
  const response = await api.put<Project>(`/projects/${projectId}/notifications`, settings);
  return response.data;
};

export const getRecentScans = async () => {
  const response = await api.get<RecentScan[]>('/projects/recent-scans');
  return response.data;
};

export const getProject = async (id: string) => {
  const response = await api.get<Project>(`/projects/${id}`);
  return response.data;
};

export const getProjectScans = async (id: string, skip: number = 0, limit: number = 20, branch?: string, sortBy: string = 'created_at', sortOrder: 'asc' | 'desc' = 'desc', excludeRescans: boolean = false) => {
  const response = await api.get<Scan[]>(`/projects/${id}/scans`, {
    params: { skip, limit, branch, sort_by: sortBy, sort_order: sortOrder, exclude_rescans: excludeRescans }
  });
  return response.data;
};

export const getScanHistory = async (projectId: string, scanId: string) => {
  const response = await api.get<Scan[]>(`/projects/${projectId}/scans/${scanId}/history`);
  return response.data;
};

export const triggerRescan = async (projectId: string, scanId: string) => {
  const response = await api.post<Scan>(`/projects/${projectId}/scans/${scanId}/rescan`);
  return response.data;
};

export const getProjectBranches = async (id: string) => {
  const response = await api.get<string[]>(`/projects/${id}/branches`);
  return response.data;
};

export const getScan = async (scanId: string) => {
  const response = await api.get<Scan>(`/projects/scans/${scanId}`);
  return response.data;
};

// SBOM Metadata types
export interface SbomToolComponent {
  name: string;
}

export interface SbomTool {
  name?: string;
  vendor?: string;
}

export interface SbomMetadata {
  component?: {
    name?: string;
  };
  tools?: SbomTool[] | {
    components?: SbomToolComponent[];
  };
}

export interface SbomData {
  metadata?: SbomMetadata;
  serialNumber?: string;
  [key: string]: unknown;
}

export interface SbomResponse {
  index: number;
  filename: string | null;
  storage: 'gridfs' | 'inline';
  sbom: SbomData | null;
  error?: string;
}

export const getScanSboms = async (scanId: string): Promise<SbomResponse[]> => {
  const response = await api.get<SbomResponse[]>(`/projects/scans/${scanId}/sboms`);
  return response.data;
};

export const getUsers = async (skip = 0, limit = 20, search?: string, sortBy = 'username', sortOrder = 'asc') => {
  const params = new URLSearchParams();
  params.append('skip', skip.toString());
  params.append('limit', limit.toString());
  if (search) params.append('search', search);
  params.append('sort_by', sortBy);
  params.append('sort_order', sortOrder);
  
  const response = await api.get<User[]>('/users/', { params });
  return response.data;
};

export interface UserCreate {
  username: string;
  email: string;
  password: string;
  permissions?: string[];
  is_active?: boolean;
}

export const createUser = async (data: UserCreate) => {
  const response = await api.post<User>('/users/', data);
  return response.data;
};

export interface UserUpdate {
  permissions?: string[];
  password?: string;
  is_active?: boolean;
}

export const updateUser = async (userId: string, data: UserUpdate) => {
  const response = await api.put<User>(`/users/${userId}`, data);
  return response.data;
};

export interface TeamMember {
  user_id: string;
  username?: string;
  role: string;
}

export interface Team {
  _id: string;
  name: string;
  description?: string;
  members: TeamMember[];
  created_at: string;
  updated_at: string;
}

export const getTeams = async (search?: string, sortBy = 'name', sortOrder = 'asc') => {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  params.append('sort_by', sortBy);
  params.append('sort_order', sortOrder);
  const response = await api.get<Team[]>('/teams/', { params });
  return response.data;
};

export const createTeam = async (name: string, description?: string) => {
  const response = await api.post<Team>('/teams/', { name, description });
  return response.data;
};

export const addTeamMember = async (teamId: string, email: string, role: string) => {
  const response = await api.post<Team>(`/teams/${teamId}/members`, { email, role });
  return response.data;
};

export const deleteTeam = async (teamId: string) => {
  await api.delete(`/teams/${teamId}`);
};

export const updatePassword = async (currentPassword: string, newPassword: string) => {
  const response = await api.post<User>('/users/me/password', { current_password: currentPassword, new_password: newPassword });
  return response.data;
};

export const migrateToLocal = async (newPassword: string) => {
  const response = await api.post<User>('/users/me/migrate-to-local', { new_password: newPassword });
  return response.data;
};

export const adminMigrateUserToLocal = async (userId: string) => {
  const response = await api.post<User>(`/users/${userId}/migrate`);
  return response.data;
};

export const adminResetUserPassword = async (userId: string) => {
  const response = await api.post<{ message: string, email_sent: boolean, reset_link?: string }>(`/users/${userId}/reset-password`);
  return response.data;
};

export const adminDisableUser2FA = async (userId: string) => {
  const response = await api.post<User>(`/users/${userId}/2fa/disable`);
  return response.data;
};

export const resetPassword = async (token: string, newPassword: string) => {
  const response = await api.post<{ message: string }>('/reset-password', { token, new_password: newPassword });
  return response.data;
};

export interface UserUpdateMe {
  email?: string;
  username?: string;
  slack_username?: string;
  mattermost_username?: string;
}

export const updateMe = async (data: UserUpdateMe) => {
  const response = await api.patch<User>('/users/me', data);
  return response.data;
};

export interface TwoFASetup {
  secret: string;
  qr_code: string;
}

export const setup2FA = async () => {
  const response = await api.post<TwoFASetup>('/users/me/2fa/setup');
  return response.data;
};

export const enable2FA = async (code: string, password: string) => {
  const response = await api.post<User>('/users/me/2fa/enable', { code, password });
  return response.data;
};

export const disable2FA = async (password: string) => {
  const response = await api.post<User>('/users/me/2fa/disable', { password });
  return response.data;
};

// Interceptor logic
let isRefreshing = false;

interface QueueItem {
  resolve: (value: string | null) => void;
  reject: (error: Error) => void;
}
let failedQueue: QueueItem[] = [];

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });

  failedQueue = [];
};

let onLogout: () => void = () => {};

export const setLogoutCallback = (callback: () => void) => {
    onLogout = callback;
}

api.interceptors.response.use(
  (response) => {
    logger.debug(`Response: ${response.status} ${response.config.url}`);
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status !== 401) {
        logger.error(`Response Error: ${error.response?.status} ${error.config?.url}`, error.response?.data || error.message);
    }

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise(function(resolve, reject) {
          failedQueue.push({resolve, reject});
        }).then(token => {
          originalRequest.headers['Authorization'] = 'Bearer ' + token;
          return api(originalRequest);
        }).catch(err => {
          return Promise.reject(err);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshTokenValue = localStorage.getItem('refresh_token');
      
      if (!refreshTokenValue) {
          isRefreshing = false;
          onLogout();
          return Promise.reject(error);
      }

      try {
        // Use a new axios instance to avoid interceptor loop
        const baseUrl = getBaseUrl();
        const url = baseUrl.endsWith('/') ? `${baseUrl}login/refresh-token` : `${baseUrl}/login/refresh-token`;
        const response = await axios.post<Token>(url, {
            refresh_token: refreshTokenValue
        });

        const { access_token, refresh_token } = response.data;

        localStorage.setItem('token', access_token);
        if (refresh_token) {
            localStorage.setItem('refresh_token', refresh_token);
        }

        api.defaults.headers.common['Authorization'] = 'Bearer ' + access_token;
        originalRequest.headers['Authorization'] = 'Bearer ' + access_token;

        processQueue(null, access_token);
        isRefreshing = false;

        return api(originalRequest);
      } catch (err) {
        processQueue(err instanceof Error ? err : new Error(String(err)), null);
        isRefreshing = false;
        onLogout();
        return Promise.reject(err);
      }
    }

    return Promise.reject(error);
  }
);

export interface Waiver {
  id: string;
  project_id?: string;
  finding_id?: string;
  vulnerability_id?: string;
  package_name?: string;
  package_version?: string;
  finding_type?: string;
  reason: string;
  status: string;
  expiration_date?: string;
  created_by: string;
  created_at: string;
}

export interface WaiverCreate {
  project_id?: string;
  finding_id?: string;
  vulnerability_id?: string;  // For granular CVE-level waivers within aggregated findings
  package_name?: string;
  package_version?: string;
  finding_type?: string;
  reason: string;
  expiration_date?: string;
}

export const getWaivers = async (projectId?: string) => {
  const params = new URLSearchParams();
  if (projectId) params.append('project_id', projectId);
  const response = await api.get<Waiver[]>('/waivers/', { params });
  return response.data;
};

export const createWaiver = async (data: WaiverCreate) => {
  const response = await api.post<Waiver>('/waivers/', data);
  return response.data;
};

export const deleteWaiver = async (waiverId: string) => {
  await api.delete(`/waivers/${waiverId}`);
};

export interface SystemSettings {
  instance_name: string;
  allow_public_registration: boolean;
  enforce_2fa: boolean;
  enforce_email_verification: boolean;
  smtp_host?: string;
  smtp_port: number;
  smtp_user?: string;
  smtp_password?: string;
  smtp_encryption?: 'starttls' | 'ssl' | 'none';
  emails_from_email: string;
  
  // Integrations
  github_token?: string;
  open_source_malware_api_key?: string;
  slack_bot_token?: string;
  slack_client_id?: string;
  slack_client_secret?: string;
  mattermost_bot_token?: string;
  mattermost_url?: string;
  
  // OIDC
  oidc_enabled: boolean;
  oidc_provider_name: string;
  gitlab_access_token?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_issuer?: string;
  oidc_authorization_endpoint?: string;
  oidc_token_endpoint?: string;
  oidc_userinfo_endpoint?: string;
  oidc_scopes: string;

  // GitLab Integration
  gitlab_integration_enabled: boolean;
  gitlab_url: string;
  gitlab_auto_create_projects: boolean;
  gitlab_sync_teams: boolean;

  // Retention
  retention_mode: 'project' | 'global';
  global_retention_days: number;
  
  // Periodic Scanning
  rescan_mode: 'project' | 'global';
  global_rescan_enabled: boolean;
  global_rescan_interval: number;
}

export const getSystemSettings = async () => {
  const response = await api.get<SystemSettings>('/system/');
  return response.data;
};

export const updateSystemSettings = async (settings: Partial<SystemSettings>) => {
  const response = await api.put<SystemSettings>('/system/', settings);
  return response.data;
};

export interface Webhook {
  id: string;
  project_id?: string;
  url: string;
  events: string[];
  secret?: string;
  is_active: boolean;
  created_at: string;
  last_triggered_at?: string;
}

export interface WebhookCreate {
  url: string;
  events: string[];
  secret?: string;
}

export const getProjectWebhooks = async (projectId: string) => {
  const response = await api.get<Webhook[]>(`/webhooks/project/${projectId}`);
  return response.data;
};

export const createProjectWebhook = async (projectId: string, data: WebhookCreate) => {
  const response = await api.post<Webhook>(`/webhooks/project/${projectId}`, data);
  return response.data;
};

export const getGlobalWebhooks = async () => {
  const response = await api.get<Webhook[]>('/webhooks/global/');
  return response.data;
};

export const createGlobalWebhook = async (data: WebhookCreate) => {
  const response = await api.post<Webhook>('/webhooks/global/', data);
  return response.data;
};

export const deleteWebhook = async (webhookId: string) => {
  await api.delete(`/webhooks/${webhookId}`);
};

// Missing Project Endpoints
export const exportProjectCsv = async (projectId: string) => {
  const response = await api.get(`/projects/${projectId}/export/csv`, { responseType: 'blob' });
  return response.data;
};

export const exportProjectSbom = async (projectId: string) => {
  const response = await api.get(`/projects/${projectId}/export/sbom`, { responseType: 'blob' });
  return response.data;
};

export const inviteProjectMember = async (projectId: string, email: string, role: string) => {
  const response = await api.post(`/projects/${projectId}/invite`, { email, role });
  return response.data;
};

export const updateProjectMember = async (projectId: string, userId: string, role: string) => {
  const response = await api.put(`/projects/${projectId}/members/${userId}`, { role });
  return response.data;
};

export const removeProjectMember = async (projectId: string, userId: string) => {
  const response = await api.delete(`/projects/${projectId}/members/${userId}`);
  return response.data;
};

// Missing Team Endpoints
export const updateTeam = async (teamId: string, name: string, description?: string) => {
  const response = await api.put<Team>(`/teams/${teamId}`, { name, description });
  return response.data;
};

export const updateTeamMember = async (teamId: string, userId: string, role: string) => {
  const response = await api.put<Team>(`/teams/${teamId}/members/${userId}`, { role });
  return response.data;
};

export const removeTeamMember = async (teamId: string, userId: string) => {
  const response = await api.delete(`/teams/${teamId}/members/${userId}`);
  return response.data;
};

// Missing User Endpoints
export const deleteUser = async (userId: string) => {
  await api.delete(`/users/${userId}`);
};

// Invitation Endpoints
export const inviteUser = async (email: string) => {
  const response = await api.post<{ message: string, link: string }>('/invitations/system', { email });
  return response.data;
};

export const validateInvitation = async (token: string) => {
  const response = await api.get<{ email: string }>(`/invitations/system/${token}`);
  return response.data;
};

export const acceptInvitation = async (token: string, username: string, password: string) => {
  const response = await api.post<User>('/invitations/system/accept', { token, username, password });
  return response.data;
};

// Search Endpoints (uses analytics API)
export interface SearchResult {
  project_id: string;
  project_name: string;
  package: string;
  version: string;
  type: string;
  license?: string;
  direct?: boolean;
  purl?: string;
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  locations?: string[];
}

export const searchDependencies = async (query: string, version?: string) => {
  const params = new URLSearchParams();
  params.append('q', query);
  if (version) params.append('version', version);
  
  const response = await api.get<SearchResult[]>('/analytics/search', { params });
  return response.data;
};

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

export const getDashboardStats = async () => {
    const response = await api.get<DashboardStats>('/projects/dashboard/stats');
    return response.data;
};

export interface ScanFindingsParams {
  skip?: number;
  limit?: number;
  sort_by?: string;
  sort_order?: string;
  type?: string;
  category?: string;
  severity?: string;
  search?: string;
}

export interface ScanFindingsResponse {
  items: Finding[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export const getScanFindings = async (scanId: string, params: ScanFindingsParams = {}) => {
  const response = await api.get<ScanFindingsResponse>(`/projects/scans/${scanId}/findings`, { params });
  return response.data;
};

export const getScanStats = async (scanId: string) => {
  const response = await api.get<Record<string, number>>(`/projects/scans/${scanId}/stats`);
  return response.data;
};

// ============ Analytics API ============

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
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
  // EPSS/KEV enrichment fields
  max_epss_score?: number;
  epss_percentile?: number;
  has_kev?: boolean;
  kev_count?: number;
  kev_ransomware_use?: boolean;
  kev_due_date?: string;
  days_until_due?: number;  // Days until CISA deadline (negative = overdue)
  exploit_maturity?: string;
  max_risk_score?: number;
  days_known?: number;
  has_fix?: boolean;
  fix_versions?: string[];
  priority_reasons?: string[];  // Human-readable priority explanations
}

export interface VulnerabilityHotspot {
  component: string;
  version: string;
  type: string;
  finding_count: number;
  severity_breakdown: SeverityBreakdown;
  affected_projects: string[];
  first_seen: string;
  // EPSS/KEV enrichment fields
  max_epss_score?: number;
  epss_percentile?: number;
  has_kev?: boolean;
  kev_count?: number;
  kev_ransomware_use?: boolean;
  kev_due_date?: string;
  days_until_due?: number;  // Days until CISA deadline (negative = overdue)
  exploit_maturity?: string;
  max_risk_score?: number;
  days_known?: number;
  has_fix?: boolean;
  fix_versions?: string[];
  top_cves?: string[];
  priority_reasons?: string[];  // Human-readable priority explanations
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
  purl?: string;
  source_type?: string;
  source_target?: string;
  layer_digest?: string;
  locations?: string[];
  // Extended fields from SBOM
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
  
  // Aggregated license information (from SBOM + deps.dev + license scanner)
  license_category?: string;  // permissive, copyleft, etc.
  licenses_detailed?: Array<{
    spdx_id: string;
    source: string;
    category?: string;
    explanation?: string;
  }>;
  license_risks?: string[];
  license_obligations?: string[];
  
  // Enrichment sources tracking
  enrichment_sources?: string[];
  
  // deps.dev enrichment data
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

export const getAnalyticsSummary = async () => {
  const response = await api.get<AnalyticsSummary>('/analytics/summary');
  return response.data;
};

export const getTopDependencies = async (limit = 20, type?: string) => {
  const params = new URLSearchParams();
  params.append('limit', limit.toString());
  if (type) params.append('type', type);
  const response = await api.get<DependencyUsage[]>('/analytics/dependencies/top', { params });
  return response.data;
};

export const getDependencyTree = async (projectId: string, scanId?: string) => {
  const params = new URLSearchParams();
  if (scanId) params.append('scan_id', scanId);
  const response = await api.get<DependencyTreeNode[]>(`/analytics/projects/${projectId}/dependency-tree`, { params });
  return response.data;
};

export const getImpactAnalysis = async (limit = 20) => {
  const params = new URLSearchParams();
  params.append('limit', limit.toString());
  const response = await api.get<ImpactAnalysisResult[]>('/analytics/impact', { params });
  return response.data;
};

export interface HotspotsQueryParams {
  skip?: number;
  limit?: number;
  sort_by?: 'finding_count' | 'component' | 'first_seen' | 'epss' | 'risk';
  sort_order?: 'asc' | 'desc';
}

export const getVulnerabilityHotspots = async (params: HotspotsQueryParams = {}) => {
  const urlParams = new URLSearchParams();
  if (params.skip !== undefined) urlParams.append('skip', params.skip.toString());
  urlParams.append('limit', (params.limit ?? 20).toString());
  if (params.sort_by) urlParams.append('sort_by', params.sort_by);
  if (params.sort_order) urlParams.append('sort_order', params.sort_order);
  const response = await api.get<VulnerabilityHotspot[]>('/analytics/hotspots', { params: urlParams });
  return response.data;
};

export interface AdvancedSearchResponse {
  items: AdvancedSearchResult[];
  total: number;
  page: number;
  size: number;
}

export const searchDependenciesAdvanced = async (
  query: string, 
  options?: {
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
): Promise<AdvancedSearchResponse> => {
  const params = new URLSearchParams();
  params.append('q', query);
  if (options?.version) params.append('version', options.version);
  if (options?.type) params.append('type', options.type);
  if (options?.source_type) params.append('source_type', options.source_type);
  if (options?.has_vulnerabilities !== undefined) {
    params.append('has_vulnerabilities', options.has_vulnerabilities.toString());
  }
  if (options?.project_ids?.length) {
    params.append('project_ids', options.project_ids.join(','));
  }
  if (options?.sort_by) params.append('sort_by', options.sort_by);
  if (options?.sort_order) params.append('sort_order', options.sort_order);
  if (options?.skip !== undefined) params.append('skip', options.skip.toString());
  if (options?.limit) params.append('limit', options.limit.toString());
  const response = await api.get<AdvancedSearchResponse>('/analytics/search', { params });
  return response.data;
};

// ============ Vulnerability Search API ============

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

export const searchVulnerabilities = async (
  query: string,
  options?: VulnerabilitySearchOptions
): Promise<VulnerabilitySearchResponse> => {
  const params = new URLSearchParams();
  params.append('q', query);
  if (options?.severity) params.append('severity', options.severity);
  if (options?.in_kev !== undefined) params.append('in_kev', options.in_kev.toString());
  if (options?.has_fix !== undefined) params.append('has_fix', options.has_fix.toString());
  if (options?.finding_type) params.append('finding_type', options.finding_type);
  if (options?.project_ids?.length) {
    params.append('project_ids', options.project_ids.join(','));
  }
  if (options?.include_waived !== undefined) {
    params.append('include_waived', options.include_waived.toString());
  }
  if (options?.sort_by) params.append('sort_by', options.sort_by);
  if (options?.sort_order) params.append('sort_order', options.sort_order);
  if (options?.skip !== undefined) params.append('skip', options.skip.toString());
  if (options?.limit) params.append('limit', options.limit.toString());
  const response = await api.get<VulnerabilitySearchResponse>('/analytics/vulnerability-search', { params });
  return response.data;
};

export type ComponentFinding = Finding & { project_id: string; project_name: string; scan_id?: string };

export const getComponentFindings = async (component: string, version?: string) => {
  const params = new URLSearchParams();
  params.append('component', component);
  if (version) params.append('version', version);
  const response = await api.get<ComponentFinding[]>('/analytics/component-findings', { params });
  return response.data;
};

// Aggregated dependency metadata (cross-project)
export interface DependencyMetadata {
  name: string;
  version: string;
  type: string;
  purl?: string;
  
  // Package metadata
  description?: string;
  author?: string;
  publisher?: string;
  homepage?: string;
  repository_url?: string;
  download_url?: string;
  group?: string;
  
  // License
  license?: string;
  license_url?: string;
  license_category?: string;
  license_risks?: string[];
  license_obligations?: string[];
  
  // deps.dev data
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
  
  // Aggregated info
  project_count: number;
  affected_projects: Array<{ id: string; name: string; direct: boolean }>;
  total_vulnerability_count: number;
  total_finding_count: number;
  
  enrichment_sources?: string[];
}

export const getDependencyMetadata = async (
  component: string, 
  version?: string, 
  type?: string
): Promise<DependencyMetadata | null> => {
  const params = new URLSearchParams();
  params.append('component', component);
  if (version) params.append('version', version);
  if (type) params.append('type', type);
  const response = await api.get<DependencyMetadata | null>('/analytics/dependency-metadata', { params });
  return response.data;
};

export const getDependencyTypes = async () => {
  const response = await api.get<string[]>('/analytics/dependency-types');
  return response.data;
};

// ============ Recommendations API ============

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
  // Dependency Health & Hygiene
  | 'outdated_dependency'
  | 'version_fragmentation'
  | 'dev_in_production'
  | 'unmaintained_package'
  // Trend-based
  | 'recurring_vulnerability'
  | 'regression_detected'
  // Dependency Graph
  | 'deep_dependency_chain'
  | 'duplicate_functionality'
  // Cross-Project
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

// Cross-project CVE entry
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
  // New fields for non-vulnerability recommendations
  file_path?: string;
  line_number?: number;
  secret_type?: string;
  files?: string[];
  rule_ids?: string[];
  license_type?: string;
  components?: string[];
  resource_type?: string;
  description?: string;
  // Dependency Health fields
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
  // Trend fields
  new_critical_cves?: string[];
  delta?: number;
  // Dependency Graph fields
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
  // Cross-Project fields
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
  // Vulnerability-related
  base_image_updates: number;
  direct_updates: number;
  transitive_updates: number;
  no_fix: number;
  total_fixable_vulns: number;
  total_unfixable_vulns: number;
  // Other finding types
  secrets_to_rotate: number;
  sast_issues: number;
  iac_issues: number;
  license_issues: number;
  quality_issues: number;
  // New categories
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

export const getProjectRecommendations = async (projectId: string, scanId?: string) => {
  const params = scanId ? `?scan_id=${scanId}` : '';
  const response = await api.get<RecommendationsResponse>(`/analytics/projects/${projectId}/recommendations${params}`);
  return response.data;
};

export default api;

