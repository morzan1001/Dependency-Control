import type { PaginatedResponse } from './common';

export interface GitHubInstance {
  id: string;
  name: string;
  url: string;
  github_url?: string;
  description?: string;
  is_active: boolean;
  oidc_audience?: string;
  auto_create_projects: boolean;
  sync_teams: boolean;
  allowed_owner_ids: string[];
  token_configured: boolean;
  created_at: string;
  created_by: string;
  last_modified_at?: string;
}

export interface GitHubInstanceCreate {
  name: string;
  url: string;
  github_url?: string;
  description?: string;
  is_active?: boolean;
  oidc_audience: string;
  auto_create_projects?: boolean;
  sync_teams?: boolean;
  access_token?: string;
  allowed_owner_ids?: string[];
}

export interface GitHubInstanceUpdate {
  name?: string;
  url?: string;
  github_url?: string | null;
  description?: string | null;
  is_active?: boolean;
  oidc_audience?: string;
  auto_create_projects?: boolean;
  sync_teams?: boolean;
  access_token?: string;
  allowed_owner_ids?: string[];
}

export type GitHubInstanceList = PaginatedResponse<GitHubInstance>;

export interface GitHubOrgTeam {
  id: number;
  slug: string;
  name: string;
  parent_name?: string | null;
}

export interface GitHubInstanceTestConnectionResponse {
  success: boolean;
  message: string;
  instance_name: string;
  url: string;
}
