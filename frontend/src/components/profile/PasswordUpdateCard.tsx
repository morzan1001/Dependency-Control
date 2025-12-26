import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { updatePassword, migrateToLocal, User, ApiError } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

interface PasswordUpdateCardProps {
  user?: User;
}

export function PasswordUpdateCard({ user }: PasswordUpdateCardProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const queryClient = useQueryClient();

  const isLocalUser = user?.auth_provider === 'local';

  const validatePassword = (password: string) => {
    if (password.length < 8) return "Password must be at least 8 characters long";
    if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
    if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
    if (!/\d/.test(password)) return "Password must contain at least one digit";
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return "Password must contain at least one special character";
    return null;
  };

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
    onError: (error: ApiError) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const migrateToLocalMutation = useMutation({
    mutationFn: () => migrateToLocal(newPassword),
    onSuccess: () => {
      toast.success("Account Migrated", {
        description: "Your account has been migrated to local authentication. You can now login with your password.",
      });
      setNewPassword('');
      setConfirmPassword('');
      queryClient.invalidateQueries({ queryKey: ['me'] });
    },
    onError: (error: ApiError) => {
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

    const error = validatePassword(newPassword);
    if (error) {
      toast.error("Invalid Password", {
        description: error,
      });
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
          <div className="bg-blue-50 border border-blue-200 text-blue-800 rounded-md p-4 mb-4 text-sm">
            You are currently authenticated via <strong>{user?.auth_provider}</strong>. 
            You cannot change your password using the standard form. 
            However, you can set a local password below to migrate your account to a local account.
            After migration, you will be able to login with your email and password.
          </div>
        )}
        <form onSubmit={handlePasswordUpdate} className="space-y-4">
          {isLocalUser && (
            <div className="space-y-2">
              <Label htmlFor="current-password">Current Password</Label>
              <Input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
              />
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="new-password">New Password</Label>
            <Input
              id="new-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
            <p className="text-xs text-muted-foreground">
              Must be at least 8 characters and contain uppercase, lowercase, digit, and special character.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm New Password</Label>
            <Input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          <Button 
            type="submit" 
            disabled={updatePasswordMutation.isPending || migrateToLocalMutation.isPending}
          >
            {updatePasswordMutation.isPending || migrateToLocalMutation.isPending 
              ? "Updating..." 
              : (isLocalUser ? "Update Password" : "Set Password & Migrate")}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
