import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { inviteUser, getSystemSettings } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Mail } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from "@/components/ui/dialog"
import { toast } from "sonner"
import { AxiosError } from 'axios';

export function InviteUserDialog() {
  const [isOpen, setIsOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const inviteUserMutation = useMutation({
    mutationFn: (email: string) => inviteUser(email),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      queryClient.invalidateQueries({ queryKey: ['invitations'] });
      
      if (!systemSettings?.smtp_host && data.link) {
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
    onError: (error: AxiosError<any>) => {
      toast.error("Error", {
        description: error.response?.data?.detail || "Failed to send invitation",
      });
    }
  });

  const handleInviteUser = (e: React.FormEvent) => {
    e.preventDefault();
    inviteUserMutation.mutate(inviteEmail);
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => {
      setIsOpen(open);
      if (!open) {
        setInviteLink(null);
        setInviteEmail("");
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
            Send an invitation email to a new user. They will be able to set their own password.
          </DialogDescription>
        </DialogHeader>
        
        {inviteLink ? (
          <div className="space-y-4">
            <div className="p-4 bg-muted rounded-md break-all text-sm font-mono">
              {inviteLink}
            </div>
            <Button 
              className="w-full" 
              onClick={() => {
                navigator.clipboard.writeText(inviteLink);
                toast.success("Link copied to clipboard");
              }}
            >
              Copy Link
            </Button>
          </div>
        ) : (
          <form onSubmit={handleInviteUser} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="invite-email">Email</Label>
              <Input
                id="invite-email"
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                required
              />
            </div>
            <Button type="submit" className="w-full" disabled={inviteUserMutation.isPending}>
              {inviteUserMutation.isPending ? "Sending..." : "Send Invitation"}
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
