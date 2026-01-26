import { useState } from 'react';
import { useAddTeamMember } from '@/hooks/queries/use-teams';
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
import { TEAM_ROLES } from '@/lib/constants';

interface AddMemberDialogProps {
  teamId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export function AddMemberDialog({ teamId, isOpen, onClose }: AddMemberDialogProps) {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('member');
  const addMemberMutation = useAddTeamMember();

  const handleClose = () => {
    setEmail('');
    setRole('member');
    onClose();
  };

  const handleAddMember = (e: React.FormEvent) => {
    e.preventDefault();
    if (teamId) {
      addMemberMutation.mutate(
        { teamId, data: { email, role } },
        {
          onSuccess: () => {
            handleClose();
            toast.success("Member added successfully");
          }
        }
      );
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[425px]">
        <form onSubmit={handleAddMember}>
          <DialogHeader>
            <DialogTitle>Add Team Member</DialogTitle>
            <DialogDescription>
              Add a user to the team by their email address.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="email" className="text-right">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="col-span-3"
                required
              />
            </div>
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="role" className="text-right">
                Role
              </Label>
              <div className="col-span-3">
                  <Select value={role} onValueChange={setRole}>
                  <SelectTrigger>
                      <SelectValue placeholder="Select a role" />
                  </SelectTrigger>
                  <SelectContent>
                      {TEAM_ROLES.map((r) => (
                        <SelectItem key={r.value} value={r.value}>
                          {r.label}
                        </SelectItem>
                      ))}
                  </SelectContent>
                  </Select>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button type="submit" disabled={addMemberMutation.isPending}>
              {addMemberMutation.isPending ? 'Adding...' : 'Add Member'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
