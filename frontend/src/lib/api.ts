import axios from 'axios';
import { logger } from './logger';

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

export const getPublicConfig = async () => {
  const response = await api.get<{ 
    allow_public_registration: boolean, 
    enforce_2fa: boolean, 
    enforce_email_verification: boolean,
    oidc_enabled?: boolean,
    oidc_provider_name?: string
  }>('/system/public-config');
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
  auth_provider?: string;
  permissions: string[];
  totp_enabled: boolean;
  slack_username?: string;
  mattermost_username?: string;
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

export interface Project {
  _id: string;
  name: string;
  owner_id: string;
  team_id?: string;
  members?: ProjectMember[];
  active_analyzers?: string[];
  retention_days?: number;
  default_branch?: string;
  owner_notification_preferences?: {
    [key: string]: string[];
  };
  stats?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    risk_score?: number;
    [key: string]: number | undefined;
  } | null;
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
  | "other";

export interface Finding {
  id: string;
  type: FindingType;
  severity: Severity;
  component: string;
  version?: string;
  description: string;
  scanners: string[];
  details: Record<string, any>;
  found_in: string[];
  aliases: string[];
  waived: boolean;
  waiver_reason?: string;
}

export interface AnalysisResult {
  _id: string;
  scan_id: string;
  analyzer_name: string;
  result: any;
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
  created_at: string;
  status: string;
  findings_summary?: Finding[];
  findings_count?: number;
  ignored_count?: number;
  stats?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    risk_score?: number;
    [key: string]: number | undefined;
  } | null;
  completed_at?: string;
  sbom?: any;
  sboms?: any[];
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
  default_branch?: string | null;
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

export const getProjectScans = async (id: string, skip: number = 0, limit: number = 20, branch?: string, sortBy: string = 'created_at', sortOrder: 'asc' | 'desc' = 'desc') => {
  const response = await api.get<Scan[]>(`/projects/${id}/scans`, {
    params: { skip, limit, branch, sort_by: sortBy, sort_order: sortOrder }
  });
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
let failedQueue: any[] = [];

const processQueue = (error: any, token: string | null = null) => {
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
        processQueue(err, null);
        isRefreshing = false;
        onLogout();
        return Promise.reject(err);
      }
    }

    return Promise.reject(error);
  }
);

export interface Waiver {
  _id: string;
  project_id?: string;
  finding_id?: string;
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
  emails_from_email: string;
  open_source_malware_api_key?: string;
  slack_bot_token?: string;
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

// Search Endpoints
export interface SearchResult {
  project_id: string;
  project_name: string;
  package: string;
  version: string;
  type: string;
  license?: string;
}

export const searchDependencies = async (query: string, version?: string) => {
  const params = new URLSearchParams();
  params.append('q', query);
  if (version) params.append('version', version);
  
  const response = await api.get<SearchResult[]>('/search/dependencies', { params });
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

export default api;

