import { GitLabInstance } from "@/types/gitlab";
import { GitHubInstance } from "@/types/github";

export type InstanceType = "gitlab" | "github";

export type UnifiedInstance = {
  _type: InstanceType;
  id: string;
  name: string;
  url: string;
  description?: string;
  is_active: boolean;
  oidc_audience?: string;
  auto_create_projects: boolean;
  sync_teams?: boolean;
  created_at: string;
  // GitLab-specific
  is_default?: boolean;
  team_sync_depth?: number;
  token_configured?: boolean;
  // GitHub-specific
  github_url?: string;
  has_access_token?: boolean;
};

export function mergeInstances(
  gitlabItems: GitLabInstance[] | undefined,
  githubItems: GitHubInstance[] | undefined
): UnifiedInstance[] {
  const merged: UnifiedInstance[] = [];

  if (gitlabItems) {
    for (const gl of gitlabItems) {
      merged.push({
        _type: "gitlab",
        id: gl.id,
        name: gl.name,
        url: gl.url,
        description: gl.description,
        is_active: gl.is_active,
        oidc_audience: gl.oidc_audience,
        auto_create_projects: gl.auto_create_projects,
        sync_teams: gl.sync_teams,
        created_at: gl.created_at,
        is_default: gl.is_default,
        team_sync_depth: gl.team_sync_depth,
        token_configured: gl.token_configured,
      });
    }
  }

  if (githubItems) {
    for (const gh of githubItems) {
      merged.push({
        _type: "github",
        id: gh.id,
        name: gh.name,
        url: gh.url,
        description: gh.description,
        is_active: gh.is_active,
        oidc_audience: gh.oidc_audience,
        auto_create_projects: gh.auto_create_projects,
        sync_teams: gh.sync_teams,
        created_at: gh.created_at,
        github_url: gh.github_url,
        has_access_token: gh.has_access_token,
      });
    }
  }

  return merged.sort((a, b) => a.name.localeCompare(b.name));
}
