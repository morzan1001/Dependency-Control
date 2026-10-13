import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi } from '@/api/auth';
import { ApiError } from '@/api/client';
import { INVALID_OTP_CODE, INVALID_PASSWORD } from '@/hooks/queries/use-auth';
import { TwoFASetup } from '@/types/user';
import { Button } from '@/components/ui/button';
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
import { TwoFAEnableFields } from './TwoFAEnableFields';

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
      if (detail !== INVALID_OTP_CODE && detail !== INVALID_PASSWORD) toast.error("Error", { description: getErrorMessage(error) });
    }
  });

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
            <TwoFAEnableFields
              code={otpCode}
              password={password}
              error={enable2FAMutation.error}
              onCodeChange={(code) => {
                setOtpCode(code);
                resetRefusal();
              }}
              onPasswordChange={(value) => {
                setPassword(value);
                resetRefusal();
              }}
            />
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
