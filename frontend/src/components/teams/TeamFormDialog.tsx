import { useState } from 'react';
import { useCreateTeam, useTeams, useUpdateTeam } from '@/hooks/queries/use-teams';
import { isNameTaken } from '@/lib/utils';
import { Team } from '@/types/team';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { WarningHint } from '@/components/ui/warning-hint';
import { Plus } from 'lucide-react';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { toast } from "sonner"

const CREATE = { title: 'Create Team', blurb: 'Create a new team to manage projects and members.', submit: 'Create Team', pending: 'Creating...', idPrefix: '' };
const EDIT = { title: 'Edit Team', blurb: 'Update team details.', submit: 'Save Changes', pending: 'Saving...', idPrefix: 'edit-' };

// Create mode owns its trigger and open state, so an unsent draft survives closing the dialog.
export function TeamFormDialog({ team, onClose }: Readonly<{ team?: Team; onClose?: () => void }>) {
  const [isOpen, setIsOpen] = useState(false);
  const [name, setName] = useState(team?.name || '');
  const [description, setDescription] = useState(team?.description || '');
  const createTeamMutation = useCreateTeam({ errorTitle: "Failed to create team" });
  const updateTeamMutation = useUpdateTeam({ errorTitle: "Failed to update team" });
  const { data: teams } = useTeams(undefined, undefined, undefined, { enabled: !!team || isOpen });
  const nameTaken = isNameTaken(teams, name, team);
  const mode = team ? EDIT : CREATE;
  const isPending = createTeamMutation.isPending || updateTeamMutation.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (team) {
      updateTeamMutation.mutate(
        { id: team.id, data: { name, description } },
        {
          onSuccess: () => {
            onClose?.();
            toast.success("Team updated successfully");
          },
        }
      );
      return;
    }
    createTeamMutation.mutate(
      { name, description },
      {
        onSuccess: () => {
          setIsOpen(false);
          setName('');
          setDescription('');
          toast.success("Team created successfully");
        },
      }
    );
  };

  return (
    <Dialog open={!!team || isOpen} onOpenChange={team ? onClose : setIsOpen}>
      {!team && (
        <DialogTrigger asChild>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            Create Team
          </Button>
        </DialogTrigger>
      )}
      <DialogContent>
        <form onSubmit={handleSubmit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>{mode.title}</DialogTitle>
            <DialogDescription>{mode.blurb}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor={`${mode.idPrefix}name`}>Name</Label>
            <Input
              id={`${mode.idPrefix}name`}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            {nameTaken && <WarningHint>A team with this name already exists</WarningHint>}
          </div>
          <div className="grid gap-2">
            <Label htmlFor={`${mode.idPrefix}description`}>Description</Label>
            <Input
              id={`${mode.idPrefix}description`}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">Cancel</Button>
            </DialogClose>
            <Button type="submit" disabled={isPending}>
              {isPending ? mode.pending : mode.submit}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
