import { GitHubOrgTeam } from '@/types/github';
import { Team } from '@/types/team';

// A single match is no narrowing, so only an ambiguous sync gets a note.
export function githubTeamCandidatesNote(count?: number | null, teamName?: string | null): string | null {
  if (!count || count < 2) return null;
  return teamName ? `${count} teams matched, using ${teamName}` : `${count} teams matched`;
}

// Nested teams share display names across an organisation, so the parent is part of the identity.
export function githubTeamOptionLabel(team: GitHubOrgTeam): string {
  const label = `${team.name} (${team.slug})`;
  return team.parent_name ? `${label} — under ${team.parent_name}` : label;
}

// The stored binding, not the team's own name: correcting a mis-binding needs the organisation
// and the number it points at.
export function githubBindingSummary(team: Team): string | null {
  if (!team.github_org || team.github_team_id == null) return null;
  return `${team.github_org}/${team.github_team_slug ?? '?'} (#${team.github_team_id})`;
}
