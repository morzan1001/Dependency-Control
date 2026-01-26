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

export function UserDetailsCard({ user, notificationChannels }: UserDetailsCardProps) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState(user?.username || '');
  const [email, setEmail] = useState(user?.email || '');
  const [slackUsername, setSlackUsername] = useState(user?.slack_username || '');
  const [mattermostUsername, setMattermostUsername] = useState(user?.mattermost_username || '');
  const [prevUserId, setPrevUserId] = useState<string | undefined>(user?.id);

  // Sync state when user prop changes (React 19 pattern: adjust state during render)
  if (user && user.id !== prevUserId) {
    setPrevUserId(user.id);
    setUsername(user.username || '');
    setEmail(user.email || '');
    setSlackUsername(user.slack_username || '');
    setMattermostUsername(user.mattermost_username || '');
  }

  const updateProfileMutation = useMutation({
    mutationFn: () => userApi.updateMe({ 
      username, 
      email,
      slack_username: slackUsername || undefined,
      mattermost_username: mattermostUsername || undefined
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

  return (
    <Card>
      <CardHeader>
        <CardTitle>User Details</CardTitle>
        <CardDescription>Your account information</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={handleProfileUpdate} className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="username">Username</Label>
            <Input 
              id="username" 
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            <Input 
              id="email" 
              type="email" 
              value={email} 
              onChange={(e) => setEmail(e.target.value)} 
            />
          </div>

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
