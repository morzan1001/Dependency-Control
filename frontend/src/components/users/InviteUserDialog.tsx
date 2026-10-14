import { useState } from 'react';
import { refusesEmail, useInviteUser } from '@/hooks/queries/use-users';
import { useAppConfig } from '@/hooks/queries/use-system';
import { getErrorMessage } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { CopyField } from '@/components/ui/copy-field';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Mail } from 'lucide-react';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { toast } from "sonner"

export function InviteUserDialog() {
  const [isOpen, setIsOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [blankEmail, setBlankEmail] = useState(false);
  const [inviteLink, setInviteLink] = useState<string | null>(null);

  const { data: appConfig } = useAppConfig({ enabled: isOpen });

  const inviteUserMutation = useInviteUser();
  const emailRefusal =
    inviteUserMutation.isError && refusesEmail(inviteUserMutation.error) ? getErrorMessage(inviteUserMutation.error) : null;
  const emailError = blankEmail ? 'Enter an email address' : emailRefusal;

  const handleInviteUser = (e: React.FormEvent) => {
    e.preventDefault();
    const nextEmail = inviteEmail.trim();
    if (!nextEmail) {
      setBlankEmail(true);
      return;
    }
    inviteUserMutation.mutate(nextEmail, {
      onSuccess: (data) => {
        if (!appConfig?.notifications.email && data.link) {
          setInviteLink(data.link);
          toast.success("Invitation created", {
            description: "Please copy the invitation link below.",
          });
        } else {
          setIsOpen(false);
          setInviteEmail("");
          toast.success("Invitation sent", {
            description: "An invitation email has been sent to the user.",
          });
        }
      },
      onError: (error) => {
        if (!refusesEmail(error)) toast.error("Failed to send invitation", { description: getErrorMessage(error) });
      }
    });
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => {
      setIsOpen(open);
      if (!open) {
        setInviteLink(null);
        setInviteEmail("");
        setBlankEmail(false);
        if (!inviteUserMutation.isPending) inviteUserMutation.reset();
      }
    }}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Mail className="mr-2 h-4 w-4" />
          Invite User
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite User</DialogTitle>
          <DialogDescription>
            {inviteLink
              ? 'Please copy the invitation link and send it to the user.'
              : 'Send an invitation email to a new user. They will be able to set their own password.'}
          </DialogDescription>
        </DialogHeader>
        
        {inviteLink ? (
          <>
            <CopyField value={inviteLink} what="invitation link" />
            <DialogFooter>
              <DialogClose asChild>
                <Button>Close</Button>
              </DialogClose>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={handleInviteUser} className="space-y-4" noValidate>
            <div className="grid gap-2">
              <Label htmlFor="invite-email">Email</Label>
              <Input
                id="invite-email"
                type="email"
                value={inviteEmail}
                onChange={(e) => {
                  setInviteEmail(e.target.value);
                  setBlankEmail(false);
                  if (!inviteUserMutation.isPending) inviteUserMutation.reset();
                }}
                aria-invalid={!!emailError}
                aria-describedby={emailError ? 'invite-email-error' : undefined}
                required
              />
              {emailError && (
                <p id="invite-email-error" role="alert" className="text-xs text-destructive">{emailError}</p>
              )}
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button type="button" variant="outline">Cancel</Button>
              </DialogClose>
              <Button type="submit" disabled={inviteUserMutation.isPending}>
                {inviteUserMutation.isPending ? "Sending..." : "Send Invitation"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
