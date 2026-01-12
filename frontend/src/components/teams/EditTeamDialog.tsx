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
  const updateTeamMutation = useUpdateTeam();

  const handleUpdateTeam = (e: React.FormEvent) => {
    e.preventDefault();
    if (team) {
      updateTeamMutation.mutate(
        { id: team._id, data: { name, description } },
        { 
          onSuccess: () => {
             onClose();
             toast.success("Team updated successfully");
          }
        }
      );
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
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
