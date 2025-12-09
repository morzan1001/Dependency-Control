import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getMe, updatePassword, setup2FA, enable2FA, disable2FA, updateMe, TwoFASetup, getSystemSettings } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Shield, ShieldAlert } from 'lucide-react';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Spinner } from '@/components/ui/spinner';

export default function ProfilePage() {
  const queryClient = useQueryClient();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [is2FADialogOpen, setIs2FADialogOpen] = useState(false);
  const [isDisable2FADialogOpen, setIsDisable2FADialogOpen] = useState(false);
  const [twoFASetupData, setTwoFASetupData] = useState<TwoFASetup | null>(null);
  const [otpCode, setOtpCode] = useState('');
  const [passwordFor2FA, setPasswordFor2FA] = useState('');

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [slackUsername, setSlackUsername] = useState('');
  const [mattermostUsername, setMattermostUsername] = useState('');

  const { data: user, isLoading } = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
  });

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  useEffect(() => {
    if (user) {
      setUsername(user.username);
      setEmail(user.email);
      setSlackUsername(user.slack_username || '');
      setMattermostUsername(user.mattermost_username || '');
    }
  }, [user]);

  const validatePassword = (password: string) => {
    if (password.length < 8) return "Password must be at least 8 characters long";
    if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
    if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
    if (!/\d/.test(password)) return "Password must contain at least one digit";
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return "Password must contain at least one special character";
    return null;
  };

  const updateProfileMutation = useMutation({
    mutationFn: () => updateMe({ 
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
    onError: (error: any) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const updatePasswordMutation = useMutation({
    mutationFn: () => updatePassword(currentPassword, newPassword),
    onSuccess: () => {
      toast.success("Password updated", {
        description: "Your password has been updated successfully.",
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const setup2FAMutation = useMutation({
    mutationFn: setup2FA,
    onSuccess: (data) => {
      setTwoFASetupData(data);
      setIs2FADialogOpen(true);
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const enable2FAMutation = useMutation({
    mutationFn: ({ code, password }: { code: string, password: string }) => enable2FA(code, password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      setIs2FADialogOpen(false);
      setTwoFASetupData(null);
      setOtpCode('');
      setPasswordFor2FA('');
      toast.success("2FA Enabled", {
        description: "Two-factor authentication has been enabled.",
      });
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const disable2FAMutation = useMutation({
    mutationFn: (password: string) => disable2FA(password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      setIsDisable2FADialogOpen(false);
      setPasswordFor2FA('');
      toast.success("2FA Disabled", {
        description: "Two-factor authentication has been disabled.",
      });
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const handlePasswordUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      toast.error("Error", {
        description: "New passwords do not match",
      });
      return;
    }

    const validationError = validatePassword(newPassword);
    if (validationError) {
        toast.error("Invalid Password", {
            description: validationError,
        });
        return;
    }

    updatePasswordMutation.mutate();
  };

  const handleProfileUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    updateProfileMutation.mutate();
  };

  const handleEnable2FA = () => {
    enable2FAMutation.mutate({ code: otpCode, password: passwordFor2FA });
  };

  const handleDisable2FA = () => {
    disable2FAMutation.mutate(passwordFor2FA);
  };

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Spinner size={48} />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-3xl font-bold tracking-tight">Profile</h1>

      <div className="grid gap-6 md:grid-cols-2">
        {/* User Details */}
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
              
              {systemSettings?.slack_bot_token && (
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

              {systemSettings?.mattermost_url && (
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
                    <span className="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                      Inactive
                    </span>
                  )}
                </div>
              </div>
              <Button type="submit" disabled={updateProfileMutation.isPending}>
                {updateProfileMutation.isPending ? 'Saving...' : 'Save Changes'}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* 2FA Settings */}
        <Card>
          <CardHeader>
            <CardTitle>Two-Factor Authentication</CardTitle>
            <CardDescription>Manage your 2FA settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex items-center gap-3">
                {user?.totp_enabled ? (
                  <div className="p-2 bg-green-100 rounded-full">
                    <Shield className="h-6 w-6 text-green-600" />
                  </div>
                ) : (
                  <div className="p-2 bg-yellow-100 rounded-full">
                    <ShieldAlert className="h-6 w-6 text-yellow-600" />
                  </div>
                )}
                <div>
                  <div className="font-medium">Status</div>
                  <div className="text-sm text-muted-foreground">
                    {user?.totp_enabled ? 'Enabled' : 'Disabled'}
                  </div>
                </div>
              </div>
              {user?.totp_enabled ? (
                <Button variant="destructive" onClick={() => setIsDisable2FADialogOpen(true)} disabled={disable2FAMutation.isPending}>
                  Disable
                </Button>
              ) : (
                <Button onClick={() => setup2FAMutation.mutate()} disabled={setup2FAMutation.isPending}>
                  Enable
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Password Change */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Change Password</CardTitle>
            <CardDescription>Update your password</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handlePasswordUpdate} className="space-y-4 max-w-md">
              <div className="grid gap-2">
                <Label htmlFor="current-password">Current Password</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>
              <Button type="submit" disabled={updatePasswordMutation.isPending}>
                {updatePasswordMutation.isPending ? 'Updating...' : 'Update Password'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>

      {/* 2FA Setup Dialog */}
      <Dialog open={is2FADialogOpen} onOpenChange={setIs2FADialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Setup Two-Factor Authentication</DialogTitle>
            <DialogDescription>
              Scan the QR code with your authenticator app and enter the code below.
              Please confirm your password to enable 2FA.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center gap-4 py-4">
            {twoFASetupData && (
              <>
                <div className="bg-white p-4 rounded-lg">
                  <img src={`data:image/png;base64,${twoFASetupData.qr_code}`} alt="2FA QR Code" className="w-48 h-48" />
                </div>
                <div className="text-sm text-muted-foreground">
                  Secret: <code className="bg-muted px-1 py-0.5 rounded">{twoFASetupData.secret}</code>
                </div>
              </>
            )}
            <div className="w-full max-w-xs space-y-2">
              <Label htmlFor="otp">Verification Code</Label>
              <Input
                id="otp"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\s/g, ''))}
                placeholder="123456"
                className="text-center text-lg tracking-widest"
                maxLength={6}
              />
            </div>
            <div className="w-full max-w-xs space-y-2">
              <Label htmlFor="password-2fa">Password</Label>
              <Input
                id="password-2fa"
                type="password"
                value={passwordFor2FA}
                onChange={(e) => setPasswordFor2FA(e.target.value)}
                placeholder="Enter your password"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIs2FADialogOpen(false)}>Cancel</Button>
            <Button onClick={handleEnable2FA} disabled={enable2FAMutation.isPending || otpCode.length !== 6 || !passwordFor2FA}>
              {enable2FAMutation.isPending ? 'Verifying...' : 'Verify & Enable'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 2FA Disable Dialog */}
      <Dialog open={isDisable2FADialogOpen} onOpenChange={setIsDisable2FADialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable Two-Factor Authentication</DialogTitle>
            <DialogDescription>
              Are you sure you want to disable 2FA? This will make your account less secure.
              Please enter your password to confirm.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center gap-4 py-4">
            <div className="w-full max-w-xs space-y-2">
              <Label htmlFor="password-disable-2fa">Password</Label>
              <Input
                id="password-disable-2fa"
                type="password"
                value={passwordFor2FA}
                onChange={(e) => setPasswordFor2FA(e.target.value)}
                placeholder="Enter your password"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDisable2FADialogOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDisable2FA} disabled={disable2FAMutation.isPending || !passwordFor2FA}>
              {disable2FAMutation.isPending ? 'Disabling...' : 'Disable 2FA'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
