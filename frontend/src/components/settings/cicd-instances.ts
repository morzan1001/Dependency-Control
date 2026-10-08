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
  return [
    ...(gitlabItems ?? []).map((gl) => ({ ...gl, _type: "gitlab" as const })),
    ...(githubItems ?? []).map((gh) => ({ ...gh, _type: "github" as const })),
  ].sort((a, b) => a.name.localeCompare(b.name));
}
