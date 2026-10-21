import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { userApi } from '@/api/users';
import { User } from '@/types/user';
import { ApiError } from '@/api/client';
import { useAuth } from '@/context/useAuth';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

interface PasswordUpdateCardProps {
  user?: User;
}

export function PasswordUpdateCard({ user }: Readonly<PasswordUpdateCardProps>) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const queryClient = useQueryClient();
  const { logout } = useAuth();

  const isLocalUser = user?.auth_provider === 'local';
  // The server refuses a wrong current password with 400 and a new one outside the rule with 422.
  const refusesField = (error: ApiError) => {
    const status = error.response?.status;
    return (isLocalUser && status === 400) || status === 422;
  };

  const updatePasswordMutation = useMutation({
    mutationFn: () => userApi.updatePassword(currentPassword, newPassword),
    onSuccess: () => {
      toast.success("Password updated", {
        description: "Sign in with your new password.",
      });
      logout();
    },
    onError: (error: ApiError) => {
      if (!refusesField(error)) toast.error("Failed to update password", { description: getErrorMessage(error) });
    }
  });

  const migrateToLocalMutation = useMutation({
    mutationFn: () => userApi.migrateToLocal(newPassword),
    onSuccess: () => {
      toast.success("Account migrated", {
        description: "Your account has been migrated to local authentication. You can now login with your password.",
      });
      setNewPassword('');
      setConfirmPassword('');
      queryClient.invalidateQueries({ queryKey: ['me'] });
    },
    onError: (error: ApiError) => {
      if (!refusesField(error)) toast.error("Failed to migrate account", { description: getErrorMessage(error) });
    }
  });

  const isSaving = updatePasswordMutation.isPending || migrateToLocalMutation.isPending;
  const refusal = updatePasswordMutation.error ?? migrateToLocalMutation.error;
  const status = refusal?.response?.status;
  const currentPasswordError = isLocalUser && status === 400 ? getErrorMessage(refusal) : null;
  const newPasswordError = status === 422 ? getErrorMessage(refusal, { withField: false }) : null;

  const resetRefusal = () => {
    if (isSaving) return;
    updatePasswordMutation.reset();
    migrateToLocalMutation.reset();
  };

  const handlePasswordUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setMismatch(true);
      return;
    }

    if (isLocalUser) {
      updatePasswordMutation.mutate();
    } else {
      migrateToLocalMutation.mutate();
    }
  };

  if (!user) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>{isLocalUser ? "Update Password" : "Migrate to Local Account"}</CardTitle>
        <CardDescription>
          {isLocalUser 
            ? "Change your password to keep your account secure." 
            : "Set a password to enable local login and migrate your account from SSO."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!isLocalUser && (
          <div className="bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200 rounded-md p-4 mb-4 text-sm">
            You are currently authenticated via <strong className="capitalize">{user.auth_provider}</strong>.
            You cannot change your password using the standard form.
            However, you can set a local password below to migrate your account to a local account.
            After migration, you will be able to login with your email and password.
          </div>
        )}
        <form onSubmit={handlePasswordUpdate} className="space-y-4">
          {isLocalUser && (
            <div className="grid gap-2">
              <Label htmlFor="current-password">Current Password</Label>
              <Input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => {
                  setCurrentPassword(e.target.value);
                  resetRefusal();
                }}
                aria-invalid={!!currentPasswordError}
                aria-describedby={currentPasswordError ? 'current-password-error' : undefined}
                required
              />
              {currentPasswordError && (
                <p id="current-password-error" role="alert" className="text-xs text-destructive">{currentPasswordError}</p>
              )}
            </div>
          )}
          <div className="grid gap-2">
            <Label htmlFor="new-password">New Password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => {
                setNewPassword(e.target.value);
                setMismatch(false);
                resetRefusal();
              }}
              aria-invalid={!!newPasswordError}
              aria-describedby={newPasswordError ? 'new-password-error' : undefined}
              required
            />
            {newPasswordError && (
              <p id="new-password-error" role="alert" className="text-xs text-destructive">{newPasswordError}</p>
            )}
            <p className="text-xs text-muted-foreground">
              Must be at least 8 characters and contain uppercase, lowercase, digit, and special character.
            </p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="confirm-password">Confirm New Password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => {
                setConfirmPassword(e.target.value);
                setMismatch(false);
                resetRefusal();
              }}
              aria-invalid={mismatch}
              aria-describedby={mismatch ? 'confirm-password-error' : undefined}
              required
            />
            {mismatch && (
              <p id="confirm-password-error" role="alert" className="text-xs text-destructive">Passwords do not match</p>
            )}
          </div>
          <Button
            type="submit"
            disabled={isSaving}
          >
            {(() => {
              if (isSaving) return "Updating..."
              if (isLocalUser) return "Update Password"
              return "Set Password & Migrate"
            })()}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
