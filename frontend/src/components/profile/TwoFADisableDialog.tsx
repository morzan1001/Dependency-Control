import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi } from '@/api/auth';
import { ApiError } from '@/api/client';
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

export function TwoFADisableDialog({ isOpen, onClose }: TwoFADisableDialogProps) {
  const queryClient = useQueryClient();
  const [password, setPassword] = useState('');

  const disable2FAMutation = useMutation({
    mutationFn: (password: string) => authApi.disable2FA(password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      onClose();
      setPassword('');
      toast.success("2FA Disabled", {
        description: "Two-factor authentication has been disabled.",
      });
    },
    onError: (error: ApiError) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const handleDisable2FA = () => {
    disable2FAMutation.mutate(password);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
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
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Confirm your password"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
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
