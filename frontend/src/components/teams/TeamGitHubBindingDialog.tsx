import { useState } from 'react';
import { Team } from '@/types/team';
import { useSetTeamGithubBinding, useClearTeamGithubBinding } from '@/hooks/queries/use-teams';
import { useGitHubInstances, useGitHubOrgs, useGitHubOrgTeams } from '@/hooks/queries/use-instances';
import { githubBindingSummary, githubTeamOptionLabel } from '@/lib/github-team';
import { extractErrorMessage } from '@/lib/errors';
import { Button } from '@/components/ui/button';
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

interface TeamGitHubBindingDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

export function TeamGitHubBindingDialog({ team, isOpen, onClose }: TeamGitHubBindingDialogProps) {
  const [instanceId, setInstanceId] = useState<string | null>(team?.github_instance_id ?? null);
  const [org, setOrg] = useState<string | null>(team?.github_org ?? null);
  const [githubTeamId, setGithubTeamId] = useState<string | null>(
    team?.github_team_id != null ? String(team.github_team_id) : null,
  );

  const { data: instances } = useGitHubInstances({ active_only: true });
  const { data: orgs, isLoading: orgsLoading, error: orgsError } = useGitHubOrgs(instanceId);
  const { data: orgTeams, isLoading: teamsLoading, error: teamsError } = useGitHubOrgTeams(instanceId, org);

  const setBinding = useSetTeamGithubBinding();
  const clearBinding = useClearTeamGithubBinding();
  const currentBinding = team ? githubBindingSummary(team) : null;

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
    if (!team || !instanceId || !org || !githubTeamId) return;
    setBinding.mutate(
      { teamId: team.id, data: { github_instance_id: instanceId, github_org: org, github_team_id: Number(githubTeamId) } },
      {
        onSuccess: () => {
          onClose();
          toast.success("GitHub binding saved");
        },
        onError: (error) => toast.error(extractErrorMessage(error)),
      },
    );
  };

  const handleRemove = () => {
    if (!team) return;
    clearBinding.mutate(team.id, {
      onSuccess: () => {
        onClose();
        toast.success("GitHub binding removed");
      },
      onError: (error) => toast.error(extractErrorMessage(error)),
    });
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[520px]">
        <form onSubmit={handleSave}>
          <DialogHeader>
            <DialogTitle>GitHub Binding</DialogTitle>
            <DialogDescription>
              Repositories held by the bound GitHub team are assigned to {team?.name} on their next scan.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label className="text-right">Current</Label>
              <div className="col-span-3 flex items-center gap-2">
                <span className="text-sm text-muted-foreground truncate">
                  {currentBinding ?? 'Not bound — no repository resolves to this team'}
                </span>
                {currentBinding && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleRemove}
                    disabled={clearBinding.isPending}
                  >
                    Remove
                  </Button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="binding-instance" className="text-right">Instance</Label>
              <div className="col-span-3">
                <Select value={instanceId ?? ''} onValueChange={pickInstance}>
                  <SelectTrigger id="binding-instance">
                    <SelectValue placeholder="Select a GitHub instance" />
                  </SelectTrigger>
                  <SelectContent>
                    {instances?.items.map((instance) => (
                      <SelectItem key={instance.id} value={instance.id}>
                        {instance.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="binding-org" className="text-right">Organisation</Label>
              <div className="col-span-3">
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
                {orgsError && (
                  <p className="mt-1 text-xs text-destructive">{extractErrorMessage(orgsError)}</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="binding-team" className="text-right">GitHub team</Label>
              <div className="col-span-3">
                <Select
                  value={githubTeamId ?? ''}
                  onValueChange={setGithubTeamId}
                  disabled={!org || teamsLoading}
                >
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
                {teamsError && (
                  <p className="mt-1 text-xs text-destructive">{extractErrorMessage(teamsError)}</p>
                )}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button type="submit" disabled={!instanceId || !org || !githubTeamId || setBinding.isPending}>
              {setBinding.isPending ? 'Saving...' : 'Save Binding'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
