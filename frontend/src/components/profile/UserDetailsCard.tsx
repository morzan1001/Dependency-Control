import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import { useUpdateMe } from '@/hooks/queries/use-users';
import { User } from '@/types/user';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { InlineFieldForm } from '@/components/users/InlineFieldForm';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

interface UserDetailsCardProps {
  user: User | undefined;
  notificationChannels: string[] | undefined;
}

export function UserDetailsCard({ user, notificationChannels }: Readonly<UserDetailsCardProps>) {
  const queryClient = useQueryClient();
  const [slackUsername, setSlackUsername] = useState(user?.slack_username || '');
  const [mattermostUsername, setMattermostUsername] = useState(user?.mattermost_username || '');

  const chatIdsMutation = useUpdateMe();
  const renameMutation = useUpdateMe();

  const emailMutation = useMutation({
    mutationFn: (email: string) => userApi.changeEmail(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
    },
  });

  const handleChatIdsSave = (e: React.FormEvent) => {
    e.preventDefault();
    chatIdsMutation.mutate(
      { slack_username: slackUsername || null, mattermost_username: mattermostUsername || null },
      {
        onSuccess: () => toast.success("Chat IDs saved"),
        onError: (error) => toast.error("Error", { description: getErrorMessage(error) }),
      },
    );
  };

  const isLocalAccount = (user?.auth_provider || 'local') === 'local';
  const pendingEmail = emailMutation.isSuccess ? emailMutation.data.pending_email : user?.pending_email;
  const showsSlack = notificationChannels?.includes('slack');
  const showsMattermost = notificationChannels?.includes('mattermost');

  return (
    <Card>
      <CardHeader>
        <CardTitle>User Details</CardTitle>
        <CardDescription>Your account information</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <InlineFieldForm
          label="Username"
          value={user?.username || ''}
          isPending={renameMutation.isPending}
          onSave={(username) => renameMutation.mutate({ username })}
          onEdit={renameMutation.reset}
        >
          {renameMutation.isError && (
            <p role="alert" className="text-xs text-destructive">{getErrorMessage(renameMutation.error)}</p>
          )}
          {renameMutation.isSuccess && (
            <p role="status" className="text-xs text-muted-foreground">
              {isLocalAccount ? `You now sign in as ${renameMutation.data.username}.` : 'Username changed.'}
            </p>
          )}
        </InlineFieldForm>
        {isLocalAccount ? (
          <InlineFieldForm
            key={`${user?.email}|${user?.pending_email ?? ''}`}
            label="Email"
            type="email"
            value={user?.email || ''}
            isPending={emailMutation.isPending}
            onSave={(email) => emailMutation.mutate(email)}
            onEdit={emailMutation.reset}
          >
            {emailMutation.isError && (
              <p role="alert" className="text-xs text-destructive">{getErrorMessage(emailMutation.error)}</p>
            )}
            {pendingEmail && (
              <p role="status" className="text-xs text-muted-foreground">
                Open the link sent to <span className="font-medium">{pendingEmail}</span> to confirm the change. Until then, {user?.email} stays your address.
              </p>
            )}
            {emailMutation.data?.email_change === 'changed' && (
              <p role="status" className="text-xs text-muted-foreground">
                Email changed to {emailMutation.data.email}. The address is not verified.
              </p>
            )}
          </InlineFieldForm>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" value={user?.email || ''} disabled className="bg-muted" />
            <p className="text-xs text-muted-foreground">Managed by your identity provider.</p>
          </div>
        )}

        <form onSubmit={handleChatIdsSave} className="space-y-4">
          <div className="grid gap-2">
            <Label>Authentication Provider</Label>
            <Input 
              value={user?.auth_provider || 'local'} 
              disabled 
              className="bg-muted capitalize"
            />
          </div>
          
          {showsSlack && (
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

          {showsMattermost && (
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
          {(showsSlack || showsMattermost) && (
            <Button type="submit" disabled={chatIdsMutation.isPending}>
              {chatIdsMutation.isPending ? 'Saving...' : 'Save chat IDs'}
            </Button>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
