import { GitLabInstance } from "@/types/gitlab";
import { GitHubInstance } from "@/types/github";

export type InstanceType = "gitlab" | "github";

const SHARED_ISSUERS: Record<InstanceType, string> = {
  github: "https://token.actions.githubusercontent.com",
  gitlab: "https://gitlab.com",
};

// Mirrors the backend: any repository hosted behind these issuers can mint a token for them.
export function isSharedIssuer(type: InstanceType, url: string): boolean {
  return url.replace(/\/+$/, "") === SHARED_ISSUERS[type];
}

export function parseAllowlist(text: string): string[] {
  return text.split(/[\s,]+/).filter(Boolean);
}

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
  token_configured: boolean;
  created_at: string;
  // GitLab-specific
  is_default?: boolean;
  team_sync_depth?: number;
  allowed_namespaces?: string[];
  // GitHub-specific
  github_url?: string;
  allowed_owner_ids?: string[];
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
        token_configured: gl.token_configured,
        created_at: gl.created_at,
        is_default: gl.is_default,
        team_sync_depth: gl.team_sync_depth,
        allowed_namespaces: gl.allowed_namespaces,
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
        token_configured: gh.token_configured,
        created_at: gh.created_at,
        github_url: gh.github_url,
        allowed_owner_ids: gh.allowed_owner_ids,
      });
    }
  }

  return merged.sort((a, b) => a.name.localeCompare(b.name));
}
