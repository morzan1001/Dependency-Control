import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi } from '@/api/auth';
import { ApiError } from '@/api/client';
import { TwoFASetup } from '@/types/user';
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

const INVALID_CODE = 'Invalid OTP code';
const INVALID_PASSWORD = 'Invalid password';

interface TwoFASetupDialogProps {
  setupData: TwoFASetup | null;
  isOpen: boolean;
  onClose: () => void;
}

export function TwoFASetupDialog({ setupData, isOpen, onClose }: Readonly<TwoFASetupDialogProps>) {
  const queryClient = useQueryClient();
  const [otpCode, setOtpCode] = useState('');
  const [password, setPassword] = useState('');

  const handleClose = () => {
    setOtpCode('');
    setPassword('');
    enable2FAMutation.reset();
    onClose();
  };

  const enable2FAMutation = useMutation({
    mutationFn: ({ code, password }: { code: string, password: string }) => authApi.enable2FA(code, password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      handleClose();
      toast.success("2FA enabled", {
        description: "Two-factor authentication has been enabled.",
      });
    },
    onError: (error: ApiError) => {
      const detail = error.response?.data?.detail;
      if (detail !== INVALID_CODE && detail !== INVALID_PASSWORD) toast.error("Error", { description: getErrorMessage(error) });
    }
  });

  const refusal = enable2FAMutation.error?.response?.data?.detail;
  const codeError = refusal === INVALID_CODE ? refusal : null;
  const passwordError = refusal === INVALID_PASSWORD ? refusal : null;

  const resetRefusal = () => {
    if (!enable2FAMutation.isPending) enable2FAMutation.reset();
  };

  const handleEnable2FA = () => {
    enable2FAMutation.mutate({ code: otpCode, password });
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Setup Two-Factor Authentication</DialogTitle>
          <DialogDescription>
            Scan the QR code with your authenticator app and enter the code below.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col items-center gap-4 py-4">
          {setupData?.qr_code && (
            <img src={`data:image/png;base64,${setupData.qr_code}`} alt="QR Code" className="w-48 h-48" />
          )}
          <div className="text-sm text-muted-foreground">
            Secret: <code className="bg-muted px-1 py-0.5 rounded">{setupData?.secret}</code>
          </div>
          <div className="w-full space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="otp">Authenticator Code</Label>
              <Input
                id="otp"
                value={otpCode}
                onChange={(e) => {
                  setOtpCode(e.target.value);
                  resetRefusal();
                }}
                placeholder="123456"
                maxLength={6}
                inputMode="numeric"
                autoComplete="one-time-code"
                aria-invalid={!!codeError}
                aria-describedby={codeError ? 'otp-error' : undefined}
              />
              {codeError && (
                <p id="otp-error" role="alert" className="text-xs text-destructive">{codeError}</p>
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="password-2fa">Current Password</Label>
              <Input
                id="password-2fa"
                type="password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  resetRefusal();
                }}
                placeholder="Confirm your password"
                aria-invalid={!!passwordError}
                aria-describedby={passwordError ? 'password-2fa-error' : undefined}
              />
              {passwordError && (
                <p id="password-2fa-error" role="alert" className="text-xs text-destructive">{passwordError}</p>
              )}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>Cancel</Button>
          <Button 
            onClick={handleEnable2FA} 
            disabled={!otpCode || !password || enable2FAMutation.isPending}
          >
            {enable2FAMutation.isPending ? 'Enabling...' : 'Enable 2FA'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
