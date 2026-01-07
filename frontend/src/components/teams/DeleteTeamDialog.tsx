import { useDeleteTeam } from '@/hooks/queries/use-teams';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { toast } from "sonner"

interface DeleteTeamDialogProps {
  teamId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export function DeleteTeamDialog({ teamId, isOpen, onClose }: DeleteTeamDialogProps) {
  const deleteTeamMutation = useDeleteTeam();

  const handleDelete = () => {
    if (teamId) {
      deleteTeamMutation.mutate(teamId, {
        onSuccess: () => {
            onClose();
            toast.success("Team deleted successfully");
        }
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete Team</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete this team? This action cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button 
            variant="destructive" 
            onClick={handleDelete}
            disabled={deleteTeamMutation.isPending}
          >
            {deleteTeamMutation.isPending ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
