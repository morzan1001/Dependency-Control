/**
 * GitLab Instance Types
 *
 * Types for multi-GitLab instance management
 */

export interface GitLabInstance {
  id: string;
  name: string;
  url: string;
  description?: string;
  is_active: boolean;
  is_default: boolean;
  oidc_audience?: string;
  auto_create_projects: boolean;
  sync_teams: boolean;
  created_at: string;
  created_by: string;
  last_modified_at?: string;
  token_configured: boolean;
}

export interface GitLabInstanceCreate {
  name: string;
  url: string;
  description?: string;
  is_active?: boolean;
  is_default?: boolean;
  access_token: string;
  oidc_audience?: string;
  auto_create_projects?: boolean;
  sync_teams?: boolean;
}

export interface GitLabInstanceUpdate {
  name?: string;
  url?: string;
  description?: string;
  is_active?: boolean;
  is_default?: boolean;
  access_token?: string;
  oidc_audience?: string;
  auto_create_projects?: boolean;
  sync_teams?: boolean;
}

export interface GitLabInstanceList {
  items: GitLabInstance[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface GitLabInstanceTestConnectionResponse {
  success: boolean;
  message: string;
  gitlab_version?: string;
  instance_name: string;
  url: string;
}

export interface GitLabInstanceStats {
  instance_id: string;
  instance_name: string;
  project_count: number;
  active_project_count: number;
  last_scan_at?: string;
}
