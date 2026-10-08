import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import { User } from '@/types/user';
import { ApiError } from '@/api/client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

interface UserDetailsCardProps {
  user: User | undefined;
  notificationChannels: string[] | undefined;
}

function EmailChangeForm({ pendingEmail }: Readonly<{ pendingEmail: string | null | undefined }>) {
  const queryClient = useQueryClient();
  const [newEmail, setNewEmail] = useState('');

  const requestMutation = useMutation({
    mutationFn: () => userApi.requestEmailChange(newEmail),
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      setNewEmail('');
      toast.success("Confirmation link sent", {
        description: `Open the link sent to ${updated.pending_email} to finish the change.`,
      });
    },
    onError: (error: ApiError) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    requestMutation.mutate();
  };

  return (
    <form onSubmit={handleSubmit} className="grid gap-2">
      {pendingEmail && (
        <p className="text-xs text-muted-foreground">
          Waiting for confirmation of <span className="font-medium">{pendingEmail}</span>. Open the link sent there to finish the change.
        </p>
      )}
      <Label htmlFor="new-email">New email</Label>
      <div className="flex gap-2">
        <Input
          id="new-email"
          type="email"
          value={newEmail}
          onChange={(e) => setNewEmail(e.target.value)}
          required
        />
        <Button type="submit" variant="outline" disabled={requestMutation.isPending || !newEmail}>
          {requestMutation.isPending ? 'Sending...' : 'Send confirmation link'}
        </Button>
      </div>
    </form>
  );
}

export function UserDetailsCard({ user, notificationChannels }: Readonly<UserDetailsCardProps>) {
  const queryClient = useQueryClient();
  const [slackUsername, setSlackUsername] = useState(user?.slack_username || '');
  const [mattermostUsername, setMattermostUsername] = useState(user?.mattermost_username || '');

  const updateProfileMutation = useMutation({
    mutationFn: () => userApi.updateMe({
      slack_username: slackUsername || null,
      mattermost_username: mattermostUsername || null
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      toast.success("Profile updated", {
        description: "Your profile has been updated successfully.",
      });
    },
    onError: (error: ApiError) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const handleProfileUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    updateProfileMutation.mutate();
  };

  const isLocalAccount = (user?.auth_provider || 'local') === 'local';

  return (
    <Card>
      <CardHeader>
        <CardTitle>User Details</CardTitle>
        <CardDescription>Your account information</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2">
          <Label htmlFor="username">Username</Label>
          <Input id="username" value={user?.username || ''} disabled className="bg-muted" />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="email">Email</Label>
          <Input id="email" type="email" value={user?.email || ''} disabled className="bg-muted" />
          {!isLocalAccount && (
            <p className="text-xs text-muted-foreground">Managed by your identity provider.</p>
          )}
        </div>
        {isLocalAccount && <EmailChangeForm pendingEmail={user?.pending_email} />}

        <form onSubmit={handleProfileUpdate} className="space-y-4">
          <div className="grid gap-2">
            <Label>Authentication Provider</Label>
            <Input 
              value={user?.auth_provider || 'local'} 
              disabled 
              className="bg-muted capitalize"
            />
          </div>
          
          {notificationChannels?.includes('slack') && (
            <div className="grid gap-2">
              <Label htmlFor="slack-username">Slack Member ID</Label>
              <Input
                id="slack-username"
                value={slackUsername}
                onChange={(e) => setSlackUsername(e.target.value)}
                placeholder="U12345678"
              />
              <p className="text-xs text-muted-foreground">
                Your Slack Member ID (not username) for direct messages.
              </p>
            </div>
          )}

          {notificationChannels?.includes('mattermost') && (
            <div className="grid gap-2">
              <Label htmlFor="mattermost-username">Mattermost Username</Label>
              <Input 
                id="mattermost-username" 
                value={mattermostUsername} 
                onChange={(e) => setMattermostUsername(e.target.value)} 
                placeholder="username"
              />
            </div>
          )}

          <div className="grid gap-2">
            <Label>Status</Label>
            <div className="flex items-center gap-2">
              {user?.is_active ? (
                <Badge variant="default">Active</Badge>
              ) : (
                <Badge variant="destructive">Inactive</Badge>
              )}
            </div>
          </div>
          <Button type="submit" disabled={updateProfileMutation.isPending}>
            {updateProfileMutation.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
