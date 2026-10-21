import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import { emailRefusalMessage, refusesEmail, refusesUsername, useUpdateMe } from '@/hooks/queries/use-users';
import { User, UserUpdateMe } from '@/types/user';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { UserStatusBadge } from '@/components/users/UserStatusBadge';
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
  const [blankUsername, setBlankUsername] = useState(false);
  const [blankEmail, setBlankEmail] = useState(false);
  // Untouched fields follow a refetched account, so a save sends only what was edited.
  const [prevUser, setPrevUser] = useState(user);
  if (user !== prevUser) {
    setPrevUser(user);
    if (username === (prevUser?.username || '')) setUsername(user?.username || '');
    if (email === (prevUser?.email || '')) setEmail(user?.email || '');
    if (slackUsername === (prevUser?.slack_username || '')) setSlackUsername(user?.slack_username || '');
    if (mattermostUsername === (prevUser?.mattermost_username || '')) setMattermostUsername(user?.mattermost_username || '');
  }

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

  const handleSubmit = (e: React.SubmitEvent) => {
    e.preventDefault();
    const blankAddress = isLocalAccount && !nextEmail;
    if (!nextUsername || blankAddress) {
      setBlankUsername(!nextUsername);
      setBlankEmail(blankAddress);
      return;
    }
    // A save with nothing changed still sends the profile request, so it confirms like every other Save.
    if (savesProfile || !savesEmail) {
      profileMutation.mutate(profileChanges, {
        onSuccess: (saved, sent) => {
          setUsername((draft) => (draft.trim() === sent.username ? saved.username : draft));
          if (sent.username !== undefined && isLocalAccount) {
            toast.success("Profile updated", { description: `You now sign in as ${saved.username}.` });
          } else {
            toast.success("Profile updated");
          }
        },
        onError: (error, sent) => {
          if (!refusesUsername(sent, error)) toast.error("Failed to update profile", { description: getErrorMessage(error) });
        },
      });
    }
    if (savesEmail) {
      emailMutation.mutate(nextEmail, {
        onSuccess: (saved, sent) => {
          setEmail((draft) => (draft.trim() === sent ? saved.email : draft));
          if (saved.email_change === 'changed') {
            toast.success("Email changed", { description: "The address is not verified." });
          } else {
            toast.success("Confirmation link sent");
          }
        },
        onError: (error) => {
          if (!refusesEmail(error)) toast.error("Failed to change email", { description: getErrorMessage(error) });
        },
      });
    }
  };

  const usernameRefusal =
    profileMutation.isError && refusesUsername(profileMutation.variables, profileMutation.error)
      ? getErrorMessage(profileMutation.error, { withField: false })
      : null;
  const usernameError = blankUsername ? 'Enter a username' : usernameRefusal;
  const emailError = blankEmail ? 'Enter an email address' : emailRefusalMessage(emailMutation);
  const pendingEmail = emailMutation.isSuccess ? emailMutation.data.pending_email : user?.pending_email;

  return (
    <Card>
      <CardHeader>
        <CardTitle>User Details</CardTitle>
        <CardDescription>Your account information</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div className="grid gap-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                setBlankUsername(false);
                if (!profileMutation.isPending) profileMutation.reset();
              }}
              aria-invalid={!!usernameError}
              aria-describedby={usernameError ? 'username-error' : undefined}
              required
            />
            {usernameError && (
              <p id="username-error" role="alert" className="text-xs text-destructive">{usernameError}</p>
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
                    setBlankEmail(false);
                    if (!emailMutation.isPending) emailMutation.reset();
                  }}
                  aria-invalid={!!emailError}
                  aria-describedby={emailError ? 'email-error' : undefined}
                  required
                />
                {emailError && (
                  <p id="email-error" role="alert" className="text-xs text-destructive">{emailError}</p>
                )}
                {!emailError && pendingEmail && (
                  <output className="text-xs text-muted-foreground">
                    Open the link sent to <span className="font-medium">{pendingEmail}</span> to confirm the change. Until then, {user?.email} stays your address.
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
            <Label htmlFor="auth-provider">Authentication Provider</Label>
            <Input id="auth-provider" value={user?.auth_provider || 'local'} disabled className="bg-muted capitalize" />
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
              {user && <UserStatusBadge user={user} />}
            </div>
          </div>
          <Button type="submit" disabled={isSaving}>
            {isSaving ? 'Saving...' : 'Save Changes'}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
