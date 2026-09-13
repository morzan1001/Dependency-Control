import { GitHubOrgTeam } from '@/types/github';
import { GitLabGroupOption } from '@/types/gitlab';
import { BindingProvider, TeamBinding } from '@/types/team';

export const PROVIDER_LABEL: Record<BindingProvider, string> = { github: 'GitHub', gitlab: 'GitLab' };

// What the binding dialog needs of an instance of either provider: only an active one can take a
// new binding, and only one that syncs teams will ever act on it.
interface InstanceFields {
  id: string;
  name: string;
  is_active: boolean;
  sync_teams: boolean;
}

export type ProviderInstance = InstanceFields & { provider: BindingProvider };

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
// or path and the number it points at.
export function bindingSummary(binding: TeamBinding): string {
  if (binding.provider === 'github') {
    return `${binding.org}/${binding.slug ?? '?'} (#${binding.external_id})`;
  }
  return `${binding.path ?? '?'} (#${binding.external_id})`;
}

function tagged(instances: InstanceFields[], provider: BindingProvider): ProviderInstance[] {
  return instances.map(({ id, name, is_active, sync_teams }) => ({
    id,
    name,
    is_active,
    sync_teams,
    provider,
  }));
}

export function providerInstances(
  github: InstanceFields[],
  gitlab: InstanceFields[],
): ProviderInstance[] {
  return [...tagged(github, 'github'), ...tagged(gitlab, 'gitlab')];
}

// A binding on an instance that does not sync teams resolves nothing, so the offer says so rather
// than withholding the instance: sync can be switched on later and the binding then starts working.
export function instanceOptionLabel(instance: ProviderInstance): string {
  return instance.sync_teams ? instance.name : `${instance.name} — team sync off, assigns nothing`;
}
