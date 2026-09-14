import { useState } from 'react';
import { BindingProvider, Team, TeamBinding, TeamBindingRequest } from '@/types/team';
import { useSetTeamBinding, useClearTeamBinding } from '@/hooks/queries/use-teams';
import {
  useGitHubInstances,
  useGitHubOrgs,
  useGitHubOrgTeams,
  useGitLabInstances,
  useGitLabGroups,
} from '@/hooks/queries/use-instances';
import { useDebounce } from '@/hooks/use-debounce';
import {
  bindingSummary,
  githubTeamOptionLabel,
  gitlabGroupOptionLabel,
  providerInstances,
  withheldInstancesNote,
  ProviderInstance,
  PROVIDER_LABEL,
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
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { toast } from "sonner"

const STALE_INSTANCE_NOTE = 'No active instance; this binding can only be removed.';
const SYNC_OFF_NOTE = 'Team sync is off on this instance, so this binding assigns nothing.';

interface TeamBindingDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

function bindingDescription(teamName: string, providers: BindingProvider[]): string {
  const suffix = `are assigned to ${teamName} on their next scan. A team holds one binding per instance.`;
  if (providers.length === 2) {
    return `Repositories held by a bound GitHub team or GitLab group ${suffix}`;
  }
  if (providers[0] === 'github') {
    return `Repositories held by a bound GitHub team ${suffix}`;
  }
  if (providers[0] === 'gitlab') {
    return `Repositories held by a bound GitLab group ${suffix}`;
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

function BoundInstance({
  binding,
  instance,
  note,
  onRemove,
  isRemoving,
}: {
  binding: TeamBinding;
  instance?: ProviderInstance;
  note?: string;
  onRemove: () => void;
  isRemoving: boolean;
}) {
  const instanceName = instance?.name ?? binding.instance_id;
  return (
    <div className="grid grid-cols-4 items-baseline gap-4">
      <Label className="text-right">{`${PROVIDER_LABEL[binding.provider]} · ${instanceName}`}</Label>
      <div className="col-span-3">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground truncate">{bindingSummary(binding)}</span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onRemove}
            disabled={isRemoving}
            aria-label={`Remove the binding on ${instanceName}`}
          >
            Remove
          </Button>
        </div>
        {note && <p className="mt-1 text-xs text-muted-foreground">{note}</p>}
      </div>
    </div>
  );
}

// Both providers answer a refusal the same way: the 409 names the team that already holds the
// group, and that name is the whole value of the message.
function useBindingWrite(teamId: string, onSaved: () => void) {
  const setBinding = useSetTeamBinding();
  const write = (data: TeamBindingRequest) =>
    setBinding.mutate(
      { teamId, data },
      {
        onSuccess: () => {
          onSaved();
          toast.success("Binding saved");
        },
        onError: (error) => toast.error(extractErrorMessage(error)),
      },
    );
  return { write, isPending: setBinding.isPending };
}

function GitHubBindingForm({
  teamId,
  instanceId,
  onSaved,
}: {
  teamId: string;
  instanceId: string;
  onSaved: () => void;
}) {
  const [org, setOrg] = useState<string | null>(null);
  const [githubTeamId, setGithubTeamId] = useState<string | null>(null);

  const { data: orgs, isLoading: orgsLoading, error: orgsError } = useGitHubOrgs(instanceId);
  const { data: orgTeams, isLoading: teamsLoading, error: teamsError } = useGitHubOrgTeams(instanceId, org);

  const { write, isPending } = useBindingWrite(teamId, onSaved);

  const pickOrg = (value: string) => {
    setOrg(value);
    setGithubTeamId(null);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!org || !githubTeamId) return;
    write({ provider: 'github', instance_id: instanceId, org, external_id: Number(githubTeamId) });
  };

  return (
    <form onSubmit={handleSave}>
      <div className="grid gap-4 py-4">
        <FieldRow label="Organisation" htmlFor="binding-org">
          <Select value={org ?? ''} onValueChange={pickOrg} disabled={orgsLoading}>
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
        <Button type="submit" disabled={!org || !githubTeamId || isPending}>
          {isPending ? 'Saving...' : 'Save Binding'}
        </Button>
      </DialogFooter>
    </form>
  );
}

function GitLabBindingForm({
  teamId,
  instanceId,
  onSaved,
}: {
  teamId: string;
  instanceId: string;
  onSaved: () => void;
}) {
  const [groupId, setGroupId] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const debouncedSearch = useDebounce(search);

  const { data: groups, isLoading: groupsLoading, error: groupsError } = useGitLabGroups(
    instanceId,
    debouncedSearch,
  );

  const { write, isPending } = useBindingWrite(teamId, onSaved);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupId) return;
    write({ provider: 'gitlab', instance_id: instanceId, external_id: Number(groupId) });
  };

  return (
    <form onSubmit={handleSave}>
      <div className="grid gap-4 py-4">
        <FieldRow label="Find group" htmlFor="binding-group-search">
          <Input
            id="binding-group-search"
            placeholder="Filter by name or path"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </FieldRow>

        <FieldRow label="Group" htmlFor="binding-group">
          <Select value={groupId ?? ''} onValueChange={setGroupId} disabled={groupsLoading}>
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
        <Button type="submit" disabled={!groupId || isPending}>
          {isPending ? 'Saving...' : 'Save Binding'}
        </Button>
      </DialogFooter>
    </form>
  );
}

export function TeamBindingDialog({ team, isOpen, onClose }: TeamBindingDialogProps) {
  const [pickedInstanceId, setPickedInstanceId] = useState<string | null>(null);

  const { data: githubInstances, isLoading: githubLoading } = useGitHubInstances();
  const { data: gitlabInstances, isLoading: gitlabLoading } = useGitLabInstances();

  const clearBinding = useClearTeamBinding();

  const instancesLoading = githubLoading || gitlabLoading;
  const instances = providerInstances(githubInstances?.items ?? [], gitlabInstances?.items ?? []);
  const instanceById = new Map(instances.map((instance) => [instance.id, instance]));

  const bindings = team?.bindings ?? [];
  const bound = new Set(bindings.map((binding) => binding.instance_id));
  const unbound = instances.filter((instance) => instance.is_active && !bound.has(instance.id));
  const offerable = unbound.filter((instance) => instance.sync_teams);
  const withheld = unbound.filter((instance) => !instance.sync_teams);

  const activeProviders = [
    ...new Set(instances.filter((instance) => instance.is_active).map((i) => i.provider)),
  ];
  const offerableProviders = [...new Set(offerable.map((instance) => instance.provider))];

  // With a single candidate the pick is already made; the select stays for changing it.
  const selected = offerable.find(
    (instance) => instance.id === (pickedInstanceId ?? (offerable.length === 1 ? offerable[0].id : null)),
  );

  // A binding outlives the instance it names, and only its row can still clear it.
  const bindingNote = (binding: TeamBinding) => {
    if (instancesLoading) return undefined;
    const instance = instanceById.get(binding.instance_id);
    if (!instance?.is_active) return STALE_INSTANCE_NOTE;
    return instance.sync_teams ? undefined : SYNC_OFF_NOTE;
  };

  const remove = (instanceId: string) => {
    if (!team) return;
    clearBinding.mutate(
      { teamId: team.id, instanceId },
      {
        onSuccess: () => toast.success("Binding removed"),
        onError: (error) => toast.error(extractErrorMessage(error)),
      },
    );
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Team Binding</DialogTitle>
          <DialogDescription>
            {bindingDescription(team?.name ?? '', activeProviders)}
          </DialogDescription>
        </DialogHeader>

        {bindings.length > 0 && (
          <div className="grid gap-4 border-b pb-4">
            {bindings.map((binding) => (
              <BoundInstance
                key={binding.instance_id}
                binding={binding}
                instance={instanceById.get(binding.instance_id)}
                note={bindingNote(binding)}
                onRemove={() => remove(binding.instance_id)}
                isRemoving={clearBinding.isPending}
              />
            ))}
            <p className="text-xs text-muted-foreground">
              Removing a binding stops that provider from making this team an owner. The projects it owns
              by that provenance are retired on their next sync; projects owned another way keep the team.
            </p>
          </div>
        )}

        {!instancesLoading && activeProviders.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No active GitHub or GitLab instance is configured, so no binding can be made. Instances are
            managed under Settings &rarr; Integrations.
          </p>
        )}

        {!instancesLoading && activeProviders.length > 0 && unbound.length === 0 && (
          <p className="text-sm text-muted-foreground">
            This team already holds a binding on every active instance.
          </p>
        )}

        {offerable.length > 0 && (
          <FieldRow label="Instance" htmlFor="binding-instance">
            <Select value={selected?.id ?? ''} onValueChange={setPickedInstanceId}>
              <SelectTrigger id="binding-instance">
                <SelectValue placeholder="Select an instance" />
              </SelectTrigger>
              <SelectContent>
                {offerableProviders.map((provider) => (
                  <SelectGroup key={provider}>
                    <SelectLabel>{PROVIDER_LABEL[provider]}</SelectLabel>
                    {offerable
                      .filter((instance) => instance.provider === provider)
                      .map((instance) => (
                        <SelectItem key={instance.id} value={instance.id}>
                          {instance.name}
                        </SelectItem>
                      ))}
                  </SelectGroup>
                ))}
              </SelectContent>
            </Select>
          </FieldRow>
        )}

        {!instancesLoading && withheld.length > 0 && (
          <p className="text-xs text-muted-foreground">{withheldInstancesNote(withheld)}</p>
        )}

        {team && selected?.provider === 'github' && (
          <GitHubBindingForm
            key={selected.id}
            teamId={team.id}
            instanceId={selected.id}
            onSaved={() => setPickedInstanceId(null)}
          />
        )}
        {team && selected?.provider === 'gitlab' && (
          <GitLabBindingForm
            key={selected.id}
            teamId={team.id}
            instanceId={selected.id}
            onSaved={() => setPickedInstanceId(null)}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
