import { GitHubOrgTeam } from '@/types/github';
import { GitLabGroupOption } from '@/types/gitlab';
import { BindingProvider, TeamBinding } from '@/types/team';

export const PROVIDER_LABEL: Record<BindingProvider, string> = { github: 'GitHub', gitlab: 'GitLab' };

// Instance names are listed to system managers only, so anyone else sees the provider alone.
export function sourceLabel(provider: BindingProvider, instanceId: string, instanceNames: ReadonlyMap<string, string>): string {
  const name = instanceNames.get(instanceId);
  return name ? `${PROVIDER_LABEL[provider]} · ${name}` : PROVIDER_LABEL[provider];
}

// Only an active instance takes a new binding, and only one that syncs teams acts on it.
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

// The stored binding rather than the team name: fixing a mis-binding needs the org or path and its number.
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

// An instance silently missing from the offer reads as a misconfiguration, so the note names it and the toggle.
export function withheldInstancesNote(instances: ProviderInstance[]): string {
  const names = instances.map((instance) => instance.name);
  const listed =
    names.length === 1 ? names[0] : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
  return (
    `${listed} ${names.length === 1 ? 'is' : 'are'} not offered: team sync is off, so a binding ` +
    `would assign nothing. Switch it on under Settings → Integrations.`
  );
}
