import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import { useUpdateMe } from '@/hooks/queries/use-users';
import { User, UserUpdateMe } from '@/types/user';
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

export function UserDetailsCard({ user, notificationChannels }: Readonly<UserDetailsCardProps>) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState(user?.username || '');
  const [email, setEmail] = useState(user?.email || '');
  const [slackUsername, setSlackUsername] = useState(user?.slack_username || '');
  const [mattermostUsername, setMattermostUsername] = useState(user?.mattermost_username || '');

  const profileMutation = useUpdateMe();
  const emailMutation = useMutation({
    mutationFn: (email: string) => userApi.changeEmail(email),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['me'] }),
  });

  const isLocalAccount = (user?.auth_provider || 'local') === 'local';
  const nextUsername = username.trim();
  const nextEmail = email.trim();
  const profileChanges: UserUpdateMe = {};
  if (nextUsername !== (user?.username || '')) profileChanges.username = nextUsername;
  if (slackUsername !== (user?.slack_username || '')) profileChanges.slack_username = slackUsername || null;
  if (mattermostUsername !== (user?.mattermost_username || '')) profileChanges.mattermost_username = mattermostUsername || null;
  const savesProfile = Object.keys(profileChanges).length > 0;
  const savesEmail = isLocalAccount && nextEmail !== (user?.email || '');
  const isSaving = profileMutation.isPending || emailMutation.isPending;

  const saveProfile = () =>
    profileMutation.mutateAsync(profileChanges).then(
      (saved) => setUsername(saved.username),
      (error: unknown) => {
        // A refused new name shows under the username field instead.
        if (profileChanges.username === undefined) toast.error("Error", { description: getErrorMessage(error) });
        throw error;
      },
    );

  const saveEmail = () => emailMutation.mutateAsync(nextEmail).then((saved) => setEmail(saved.email));

  const handleSubmit = async (e: React.SubmitEvent) => {
    e.preventDefault();
    const saves = [];
    if (savesProfile) saves.push(saveProfile());
    if (savesEmail) saves.push(saveEmail());
    const outcomes = await Promise.allSettled(saves);
    if (outcomes.every(({ status }) => status === 'fulfilled')) toast.success("Profile updated");
  };

  const sentUsername = profileMutation.variables?.username !== undefined;
  const usernameError = sentUsername && profileMutation.isError ? getErrorMessage(profileMutation.error) : null;
  const emailError = emailMutation.isError ? getErrorMessage(emailMutation.error) : null;
  const pendingEmail = emailMutation.isSuccess ? emailMutation.data.pending_email : user?.pending_email;

  return (
    <Card>
      <CardHeader>
        <CardTitle>User Details</CardTitle>
        <CardDescription>Your account information</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                profileMutation.reset();
              }}
              aria-invalid={!!usernameError}
              aria-describedby={usernameError ? 'username-error' : undefined}
              required
            />
            {usernameError && (
              <p id="username-error" role="alert" className="text-xs text-destructive">{usernameError}</p>
            )}
            {sentUsername && profileMutation.isSuccess && isLocalAccount && (
              <output className="text-xs text-muted-foreground">
                You now sign in as {profileMutation.data.username}.
              </output>
            )}
          </div>

          <div className="grid gap-2">
            <Label htmlFor="email">Email</Label>
            {isLocalAccount ? (
              <>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    emailMutation.reset();
                  }}
                  aria-invalid={!!emailError}
                  aria-describedby={emailError ? 'email-error' : undefined}
                  required
                />
                {emailError && (
                  <p id="email-error" role="alert" className="text-xs text-destructive">{emailError}</p>
                )}
                {pendingEmail && (
                  <output className="text-xs text-muted-foreground">
                    Open the link sent to <span className="font-medium">{pendingEmail}</span> to confirm the change. Until then, {user?.email} stays your address.
                  </output>
                )}
                {emailMutation.data?.email_change === 'changed' && (
                  <output className="text-xs text-muted-foreground">
                    Email changed to {emailMutation.data.email}. The address is not verified.
                  </output>
                )}
              </>
            ) : (
              <>
                <Input id="email" type="email" value={user?.email || ''} disabled className="bg-muted" />
                <p className="text-xs text-muted-foreground">Managed by your identity provider.</p>
              </>
            )}
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
          <Button type="submit" disabled={isSaving || !nextUsername}>
            {isSaving ? 'Saving...' : 'Save Changes'}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
