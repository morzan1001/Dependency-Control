import { User } from '@/types/user';
import { getErrorMessage } from '@/lib/utils';
import { useUpdateUser } from '@/hooks/queries/use-users';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { toast } from "sonner"

interface RenameUserDialogProps {
  user: User;
  onOpenChange: (open: boolean) => void;
  onUserUpdated?: (user: User) => void;
}

export function RenameUserDialog({ user, onOpenChange, onUserUpdated }: Readonly<RenameUserDialogProps>) {
  const [username, setUsername] = useState(user.username);
  const nextUsername = username.trim();

  const updateUserMutation = useUpdateUser();

  const handleSave = (e: React.SubmitEvent) => {
    e.preventDefault();
    updateUserMutation.mutate({
      id: user.id,
      data: { username: nextUsername }
    }, {
      onSuccess: (updated) => {
        onUserUpdated?.(updated);
        toast.success("Success", {
          description: "Username updated successfully.",
        });
        onOpenChange(false);
      },
      onError: (error) => {
        toast.error("Error", {
          description: getErrorMessage(error),
        });
      },
    });
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <form onSubmit={handleSave} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Rename {user.username}</DialogTitle>
            <DialogDescription>
              Enter the new username for this user.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="rename-username">Username</Label>
            <Input
              id="rename-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={updateUserMutation.isPending || !nextUsername || nextUsername === user.username}>
              {updateUserMutation.isPending ? "Saving..." : "Save Changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
