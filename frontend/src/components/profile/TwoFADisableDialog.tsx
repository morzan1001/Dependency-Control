import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi } from '@/api/auth';
import { ApiError } from '@/api/client';
import { INVALID_PASSWORD } from '@/hooks/queries/use-auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

interface TwoFADisableDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function TwoFADisableDialog({ isOpen, onClose }: Readonly<TwoFADisableDialogProps>) {
  const queryClient = useQueryClient();
  const [password, setPassword] = useState('');

  const handleClose = () => {
    setPassword('');
    disable2FAMutation.reset();
    onClose();
  };

  const disable2FAMutation = useMutation({
    mutationFn: (password: string) => authApi.disable2FA(password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      handleClose();
      toast.success("2FA disabled", {
        description: "Two-factor authentication has been disabled.",
      });
    },
    onError: (error: ApiError) => {
      if (error.response?.data?.detail !== INVALID_PASSWORD) toast.error("Failed to disable 2FA", { description: getErrorMessage(error) });
    }
  });

  const passwordError = disable2FAMutation.error?.response?.data?.detail === INVALID_PASSWORD ? INVALID_PASSWORD : null;

  const handleDisable2FA = () => {
    disable2FAMutation.mutate(password);
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Disable Two-Factor Authentication</DialogTitle>
          <DialogDescription>
            Enter your password to disable 2FA.
          </DialogDescription>
        </DialogHeader>
        <div className="py-4">
          <div className="grid gap-2">
            <Label htmlFor="password-disable-2fa">Current Password</Label>
            <Input
              id="password-disable-2fa"
              type="password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (!disable2FAMutation.isPending) disable2FAMutation.reset();
              }}
              placeholder="Confirm your password"
              aria-invalid={!!passwordError}
              aria-describedby={passwordError ? 'password-disable-2fa-error' : undefined}
            />
            {passwordError && (
              <p id="password-disable-2fa-error" role="alert" className="text-xs text-destructive">{passwordError}</p>
            )}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>Cancel</Button>
          <Button 
            variant="destructive" 
            onClick={handleDisable2FA}
            disabled={!password || disable2FAMutation.isPending}
          >
            {disable2FAMutation.isPending ? 'Disabling...' : 'Disable 2FA'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
