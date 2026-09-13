import { GitHubOrgTeam } from '@/types/github';
import { GitLabGroupOption } from '@/types/gitlab';
import { Team } from '@/types/team';

// Nested teams share display names across an organisation, so the parent is part of the identity.
export function githubTeamOptionLabel(team: GitHubOrgTeam): string {
  const label = `${team.name} (${team.slug})`;
  return team.parent_name ? `${label} — under ${team.parent_name}` : label;
}

// Subgroups share display names across an instance, so the full path is part of the identity.
export function gitlabGroupOptionLabel(group: GitLabGroupOption): string {
  return `${group.name} (${group.full_path})`;
}

// The stored binding, not the team's own name: correcting a mis-binding needs the organisation
// and the number it points at.
export function githubBindingSummary(team: Team): string | null {
  if (!team.github_org || team.github_team_id == null) return null;
  return `${team.github_org}/${team.github_team_slug ?? '?'} (#${team.github_team_id})`;
}

export function gitlabBindingSummary(team: Team): string | null {
  if (team.gitlab_group_id == null) return null;
  return `${team.gitlab_group_path ?? '?'} (#${team.gitlab_group_id})`;
}
