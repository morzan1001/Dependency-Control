import { useState } from 'react';
import { useUpdateTeam } from '@/hooks/queries/use-teams';
import { Team } from '@/types/team';
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
import { toast } from "sonner"

interface EditTeamDialogProps {
  team: Team | null;
  isOpen: boolean;
  onClose: () => void;
}

export function EditTeamDialog({ team, isOpen, onClose }: EditTeamDialogProps) {
  const [name, setName] = useState(team?.name || '');
  const [description, setDescription] = useState(team?.description || '');
  const [prevTeamId, setPrevTeamId] = useState<string | null>(team?._id || null);
  const updateTeamMutation = useUpdateTeam();

  // Sync state when team prop changes (React 19 pattern: adjust state during render)
  if (team && team._id !== prevTeamId) {
    setPrevTeamId(team._id);
    setName(team.name || '');
    setDescription(team.description || '');
  }

  const handleClose = () => {
    setName('');
    setDescription('');
    onClose();
  };

  const handleUpdateTeam = (e: React.FormEvent) => {
    e.preventDefault();
    if (team) {
      updateTeamMutation.mutate(
        { id: team._id, data: { name, description } },
        {
          onSuccess: () => {
             handleClose();
             toast.success("Team updated successfully");
          }
        }
      );
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[425px]">
        <form onSubmit={handleUpdateTeam}>
          <DialogHeader>
            <DialogTitle>Edit Team</DialogTitle>
            <DialogDescription>
              Update team details.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="edit-name" className="text-right">
                Name
              </Label>
              <Input
                id="edit-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="col-span-3"
                required
              />
            </div>
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="edit-description" className="text-right">
                Description
              </Label>
              <Input
                id="edit-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="col-span-3"
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="submit" disabled={updateTeamMutation.isPending}>
                {updateTeamMutation.isPending ? 'Updating...' : 'Update Team'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
