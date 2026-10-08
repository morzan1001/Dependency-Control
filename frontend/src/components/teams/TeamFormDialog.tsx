import { useState } from 'react';
import { useCreateTeam, useUpdateTeam } from '@/hooks/queries/use-teams';
import { Team } from '@/types/team';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Plus } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

const CREATE = { title: 'Create Team', blurb: 'Create a new team to manage projects and members.', submit: 'Create Team', pending: 'Creating...', idPrefix: '' };
const EDIT = { title: 'Edit Team', blurb: 'Update team details.', submit: 'Update Team', pending: 'Updating...', idPrefix: 'edit-' };

// Create mode owns its trigger and open state, so an unsent draft survives closing the dialog.
export function TeamFormDialog({ team, onClose }: Readonly<{ team?: Team; onClose?: () => void }>) {
  const [isOpen, setIsOpen] = useState(false);
  const [name, setName] = useState(team?.name || '');
  const [description, setDescription] = useState(team?.description || '');
  const createTeamMutation = useCreateTeam();
  const updateTeamMutation = useUpdateTeam();
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
          onError: (error) => toast.error("Failed to update team", { description: getErrorMessage(error) }),
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
        onError: (error) => toast.error("Failed to create team", { description: getErrorMessage(error) }),
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
      <DialogContent className="sm:max-w-[425px]">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>{mode.title}</DialogTitle>
            <DialogDescription>{mode.blurb}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor={`${mode.idPrefix}name`} className="text-right">
                Name
              </Label>
              <Input
                id={`${mode.idPrefix}name`}
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="col-span-3"
                required
              />
            </div>
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor={`${mode.idPrefix}description`} className="text-right">
                Description
              </Label>
              <Input
                id={`${mode.idPrefix}description`}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="col-span-3"
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="submit" disabled={isPending}>
              {isPending ? mode.pending : mode.submit}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
