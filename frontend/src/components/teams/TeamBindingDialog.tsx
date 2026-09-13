import { useState } from 'react';
import { Team } from '@/types/team';
import {
  useSetTeamGithubBinding,
  useClearTeamGithubBinding,
  useSetTeamGitlabBinding,
  useClearTeamGitlabBinding,
} from '@/hooks/queries/use-teams';
import {
  useGitHubInstances,
  useGitHubOrgs,
  useGitHubOrgTeams,
  useGitLabInstances,
  useGitLabGroups,
} from '@/hooks/queries/use-instances';
import { useDebounce } from '@/hooks/use-debounce';
import { GitHubInstance } from '@/types/github';
import { GitLabInstance } from '@/types/gitlab';
import {
  githubBindingSummary,
  githubTeamOptionLabel,
  gitlabBindingSummary,
  gitlabGroupOptionLabel,
} from '@/lib/team-binding';
import { extractErrorMessage } from '@/lib/errors';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { toast } from "sonner"

type Provider = 'github' | 'gitlab';

const PROVIDER_LABEL: Record<Provider, string> = { github: 'GitHub', gitlab: 'GitLab' };

const STALE_INSTANCE_NOTE = 'No active instance; this binding can only be removed.';

interface TeamBindingDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

function bindingDescription(teamName: string, providers: Provider[]): string {
  const suffix = `are assigned to ${teamName} on their next scan.`;
  if (providers.length === 2) {
    return `Repositories held by the bound GitHub team or GitLab group ${suffix} A team can hold one binding per provider.`;
  }
  if (providers[0] === 'github') {
    return `Repositories held by the bound GitHub team ${suffix} A team can hold one GitHub binding.`;
  }
  if (providers[0] === 'gitlab') {
    return `Repositories held by the bound GitLab group ${suffix} A team can hold one GitLab binding.`;
  }
  return `Repositories held by a bound team or group ${suffix}`;
}

function FieldRow({ label, htmlFor, children }: { label: string; htmlFor: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-4 items-center gap-4">
      <Label htmlFor={htmlFor} className="text-right">{label}</Label>
      <div className="col-span-3">{children}</div>
    </div>
  );
}

function CurrentBinding({
  label,
  summary,
  note,
  onRemove,
  isRemoving,
}: {
  label: string;
  summary: string | null;
  note?: string;
  onRemove: () => void;
  isRemoving: boolean;
}) {
  return (
    <div className="grid grid-cols-4 items-baseline gap-4">
      <Label className="text-right">{label}</Label>
      <div className="col-span-3">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground truncate">{summary ?? 'Not bound'}</span>
          {summary && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onRemove}
              disabled={isRemoving}
              aria-label={`Remove ${label} binding`}
            >
              Remove
            </Button>
          )}
        </div>
        {note && <p className="mt-1 text-xs text-muted-foreground">{note}</p>}
      </div>
    </div>
  );
}

function GitHubBindingForm({
  team,
  instances,
  onSaved,
}: {
  team: Team;
  instances: GitHubInstance[];
  onSaved: () => void;
}) {
  const [instanceId, setInstanceId] = useState<string | null>(team.github_instance_id ?? null);
  const [org, setOrg] = useState<string | null>(team.github_org ?? null);
  const [githubTeamId, setGithubTeamId] = useState<string | null>(
    team.github_team_id != null ? String(team.github_team_id) : null,
  );

  const { data: orgs, isLoading: orgsLoading, error: orgsError } = useGitHubOrgs(instanceId);
  const { data: orgTeams, isLoading: teamsLoading, error: teamsError } = useGitHubOrgTeams(instanceId, org);

  const setBinding = useSetTeamGithubBinding();

  const pickInstance = (value: string) => {
    setInstanceId(value);
    setOrg(null);
    setGithubTeamId(null);
  };

  const pickOrg = (value: string) => {
    setOrg(value);
    setGithubTeamId(null);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!instanceId || !org || !githubTeamId) return;
    setBinding.mutate(
      { teamId: team.id, data: { github_instance_id: instanceId, github_org: org, github_team_id: Number(githubTeamId) } },
      {
        onSuccess: () => {
          onSaved();
          toast.success("GitHub binding saved");
        },
        onError: (error) => toast.error(extractErrorMessage(error)),
      },
    );
  };

  return (
    <form onSubmit={handleSave}>
      <div className="grid gap-4 py-4">
        <FieldRow label="Instance" htmlFor="binding-instance">
          <Select value={instanceId ?? ''} onValueChange={pickInstance}>
            <SelectTrigger id="binding-instance">
              <SelectValue placeholder="Select a GitHub instance" />
            </SelectTrigger>
            <SelectContent>
              {instances.map((instance) => (
                <SelectItem key={instance.id} value={instance.id}>
                  {instance.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </FieldRow>

        <FieldRow label="Organisation" htmlFor="binding-org">
          <Select value={org ?? ''} onValueChange={pickOrg} disabled={!instanceId || orgsLoading}>
            <SelectTrigger id="binding-org">
              <SelectValue placeholder={orgsLoading ? 'Loading...' : 'Select an organisation'} />
            </SelectTrigger>
            <SelectContent>
              {orgs?.map((name) => (
                <SelectItem key={name} value={name}>
                  {name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {orgsError && <p className="mt-1 text-xs text-destructive">{extractErrorMessage(orgsError)}</p>}
        </FieldRow>

        <FieldRow label="GitHub team" htmlFor="binding-team">
          <Select value={githubTeamId ?? ''} onValueChange={setGithubTeamId} disabled={!org || teamsLoading}>
            <SelectTrigger id="binding-team">
              <SelectValue placeholder={teamsLoading ? 'Loading...' : 'Select a GitHub team'} />
            </SelectTrigger>
            <SelectContent>
              {orgTeams?.map((orgTeam) => (
                <SelectItem key={orgTeam.id} value={String(orgTeam.id)}>
                  {githubTeamOptionLabel(orgTeam)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {teamsError && <p className="mt-1 text-xs text-destructive">{extractErrorMessage(teamsError)}</p>}
        </FieldRow>
      </div>
      <DialogFooter>
        <Button type="submit" disabled={!instanceId || !org || !githubTeamId || setBinding.isPending}>
          {setBinding.isPending ? 'Saving...' : 'Save Binding'}
        </Button>
      </DialogFooter>
    </form>
  );
}

function GitLabBindingForm({
  team,
  instances,
  onSaved,
}: {
  team: Team;
  instances: GitLabInstance[];
  onSaved: () => void;
}) {
  const [instanceId, setInstanceId] = useState<string | null>(team.gitlab_instance_id ?? null);
  const [groupId, setGroupId] = useState<string | null>(
    team.gitlab_group_id != null ? String(team.gitlab_group_id) : null,
  );
  const [search, setSearch] = useState('');

  const debouncedSearch = useDebounce(search);

  const { data: groups, isLoading: groupsLoading, error: groupsError } = useGitLabGroups(
    instanceId,
    debouncedSearch,
  );

  const setBinding = useSetTeamGitlabBinding();

  const pickInstance = (value: string) => {
    setInstanceId(value);
    setGroupId(null);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!instanceId || !groupId) return;
    setBinding.mutate(
      { teamId: team.id, data: { gitlab_instance_id: instanceId, gitlab_group_id: Number(groupId) } },
      {
        onSuccess: () => {
          onSaved();
          toast.success("GitLab binding saved");
        },
        onError: (error) => toast.error(extractErrorMessage(error)),
      },
    );
  };

  return (
    <form onSubmit={handleSave}>
      <div className="grid gap-4 py-4">
        <FieldRow label="Instance" htmlFor="binding-instance">
          <Select value={instanceId ?? ''} onValueChange={pickInstance}>
            <SelectTrigger id="binding-instance">
              <SelectValue placeholder="Select a GitLab instance" />
            </SelectTrigger>
            <SelectContent>
              {instances.map((instance) => (
                <SelectItem key={instance.id} value={instance.id}>
                  {instance.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </FieldRow>

        <FieldRow label="Find group" htmlFor="binding-group-search">
          <Input
            id="binding-group-search"
            placeholder="Filter by name or path"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            disabled={!instanceId}
          />
        </FieldRow>

        <FieldRow label="Group" htmlFor="binding-group">
          <Select value={groupId ?? ''} onValueChange={setGroupId} disabled={!instanceId || groupsLoading}>
            <SelectTrigger id="binding-group">
              <SelectValue placeholder={groupsLoading ? 'Loading...' : 'Select a group'} />
            </SelectTrigger>
            <SelectContent>
              {groups?.map((group) => (
                <SelectItem key={group.id} value={String(group.id)}>
                  {gitlabGroupOptionLabel(group)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {groupsError && <p className="mt-1 text-xs text-destructive">{extractErrorMessage(groupsError)}</p>}
        </FieldRow>
      </div>
      <DialogFooter>
        <Button type="submit" disabled={!instanceId || !groupId || setBinding.isPending}>
          {setBinding.isPending ? 'Saving...' : 'Save Binding'}
        </Button>
      </DialogFooter>
    </form>
  );
}

export function TeamBindingDialog({ team, isOpen, onClose }: TeamBindingDialogProps) {
  // Opens on the provider the team already answers for, which is the one an operator came to correct.
  const [provider, setProvider] = useState<Provider>(
    team?.github_team_id == null && team?.gitlab_group_id != null ? 'gitlab' : 'github',
  );

  const { data: githubInstances, isLoading: githubLoading } = useGitHubInstances({ active_only: true });
  const { data: gitlabInstances, isLoading: gitlabLoading } = useGitLabInstances({ active_only: true });

  const clearGithub = useClearTeamGithubBinding();
  const clearGitlab = useClearTeamGitlabBinding();

  const instancesLoading = githubLoading || gitlabLoading;
  const githubItems = githubInstances?.items ?? [];
  const gitlabItems = gitlabInstances?.items ?? [];

  const available: Provider[] = [
    ...(githubItems.length > 0 ? (['github'] as const) : []),
    ...(gitlabItems.length > 0 ? (['gitlab'] as const) : []),
  ];
  const activeProvider = available.includes(provider) ? provider : available[0];

  const githubSummary = team ? githubBindingSummary(team) : null;
  const gitlabSummary = team ? gitlabBindingSummary(team) : null;
  // A binding outlives its instance, and only this row can still clear it.
  const showGithubBinding = available.includes('github') || githubSummary != null;
  const showGitlabBinding = available.includes('gitlab') || gitlabSummary != null;

  const staleNote = (summary: string | null, providerAvailable: boolean) =>
    !instancesLoading && summary != null && !providerAvailable ? STALE_INSTANCE_NOTE : undefined;

  const remove = (mutation: ReturnType<typeof useClearTeamGithubBinding>, label: string) => {
    if (!team) return;
    mutation.mutate(team.id, {
      onSuccess: () => {
        onClose();
        toast.success(`${label} binding removed`);
      },
      onError: (error) => toast.error(extractErrorMessage(error)),
    });
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Team Binding</DialogTitle>
          <DialogDescription>
            {bindingDescription(team?.name ?? '', available)}
          </DialogDescription>
        </DialogHeader>

        {(showGithubBinding || showGitlabBinding) && (
          <div className="grid gap-4 border-b pb-4">
            {showGithubBinding && (
              <CurrentBinding
                label="GitHub"
                summary={githubSummary}
                note={staleNote(githubSummary, available.includes('github'))}
                onRemove={() => remove(clearGithub, 'GitHub')}
                isRemoving={clearGithub.isPending}
              />
            )}
            {showGitlabBinding && (
              <CurrentBinding
                label="GitLab"
                summary={gitlabSummary}
                note={staleNote(gitlabSummary, available.includes('gitlab'))}
                onRemove={() => remove(clearGitlab, 'GitLab')}
                isRemoving={clearGitlab.isPending}
              />
            )}
            <p className="text-xs text-muted-foreground">
              Removing a binding stops that provider from making this team an owner. The projects it owns
              by that provenance are retired on their next sync; projects owned another way keep the team.
            </p>
          </div>
        )}

        {!instancesLoading && available.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No active GitHub or GitLab instance is configured, so no binding can be made. Instances are
            managed under Settings &rarr; Integrations.
          </p>
        )}

        {available.length > 1 && (
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="binding-provider" className="text-right">Provider</Label>
            <div className="col-span-3">
              <Select value={provider} onValueChange={(value) => setProvider(value as Provider)}>
                <SelectTrigger id="binding-provider">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {available.map((option) => (
                    <SelectItem key={option} value={option}>
                      {PROVIDER_LABEL[option]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        )}

        {team && activeProvider === 'github' && (
          <GitHubBindingForm team={team} instances={githubItems} onSaved={onClose} />
        )}
        {team && activeProvider === 'gitlab' && (
          <GitLabBindingForm team={team} instances={gitlabItems} onSaved={onClose} />
        )}
      </DialogContent>
    </Dialog>
  );
}
