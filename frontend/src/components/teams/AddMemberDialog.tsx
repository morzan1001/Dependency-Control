import { useState } from 'react';
import { useAddTeamMember } from '@/hooks/queries/use-teams';
import { refusesEmail } from '@/hooks/queries/use-users';
import { getErrorMessage } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogClose,
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

export function AddMemberDialog({ teamId, isOpen, onClose }: Readonly<AddMemberDialogProps>) {
  const [email, setEmail] = useState('');
  const [blankEmail, setBlankEmail] = useState(false);
  const [role, setRole] = useState('member');
  const addMemberMutation = useAddTeamMember();
  const emailRefusal =
    addMemberMutation.isError && refusesEmail(addMemberMutation.error) ? getErrorMessage(addMemberMutation.error) : null;
  const emailError = blankEmail ? 'Enter an email address' : emailRefusal;

  const handleClose = () => {
    setEmail('');
    setBlankEmail(false);
    setRole('member');
    if (!addMemberMutation.isPending) addMemberMutation.reset();
    onClose();
  };

  const handleAddMember = (e: React.FormEvent) => {
    e.preventDefault();
    const nextEmail = email.trim();
    if (!nextEmail) {
      setBlankEmail(true);
      return;
    }
    if (teamId) {
      addMemberMutation.mutate(
        { teamId, data: { email: nextEmail, role } },
        {
          onSuccess: () => {
            handleClose();
            toast.success("Member added successfully");
          },
          onError: (error) => {
            if (!refusesEmail(error)) toast.error("Failed to add member", { description: getErrorMessage(error) });
          },
        }
      );
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent>
        <form onSubmit={handleAddMember} className="grid gap-4" noValidate>
          <DialogHeader>
            <DialogTitle>Add Team Member</DialogTitle>
            <DialogDescription>
              Add a user to the team by their email address.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setBlankEmail(false);
                if (!addMemberMutation.isPending) addMemberMutation.reset();
              }}
              aria-invalid={!!emailError}
              aria-describedby={emailError ? 'add-member-email-error' : undefined}
              required
            />
            {emailError && (
              <p id="add-member-email-error" role="alert" className="text-xs text-destructive">{emailError}</p>
            )}
          </div>
          <div className="grid gap-2">
            <Label htmlFor="role">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger id="role">
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
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">Cancel</Button>
            </DialogClose>
            <Button type="submit" disabled={addMemberMutation.isPending}>
              {addMemberMutation.isPending ? 'Adding...' : 'Add Member'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
