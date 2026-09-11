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
  has_access_token?: boolean;
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
  oidc_audience?: string;
  auto_create_projects?: boolean;
  sync_teams?: boolean;
  access_token?: string;
}

export interface GitHubInstanceUpdate {
  name?: string;
  url?: string;
  github_url?: string;
  description?: string;
  is_active?: boolean;
  oidc_audience?: string;
  auto_create_projects?: boolean;
  sync_teams?: boolean;
  access_token?: string;
}

export interface GitHubInstanceList {
  items: GitHubInstance[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface GitHubOrgTeam {
  id: number;
  slug: string;
  name: string;
  parent_slug?: string | null;
  parent_name?: string | null;
}

export interface GitHubInstanceTestConnectionResponse {
  success: boolean;
  message: string;
  instance_name: string;
  url: string;
}
