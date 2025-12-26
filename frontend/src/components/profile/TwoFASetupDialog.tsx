import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { enable2FA, TwoFASetup, ApiError } from '@/lib/api';
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

interface TwoFASetupDialogProps {
  setupData: TwoFASetup | null;
  isOpen: boolean;
  onClose: () => void;
}

export function TwoFASetupDialog({ setupData, isOpen, onClose }: TwoFASetupDialogProps) {
  const queryClient = useQueryClient();
  const [otpCode, setOtpCode] = useState('');
  const [password, setPassword] = useState('');

  const enable2FAMutation = useMutation({
    mutationFn: ({ code, password }: { code: string, password: string }) => enable2FA(code, password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      onClose();
      setOtpCode('');
      setPassword('');
      toast.success("2FA Enabled", {
        description: "Two-factor authentication has been enabled.",
      });
    },
    onError: (error: ApiError) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  const handleEnable2FA = () => {
    enable2FAMutation.mutate({ code: otpCode, password });
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
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
                onChange={(e) => setOtpCode(e.target.value)}
                placeholder="123456"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="password-2fa">Current Password</Label>
              <Input
                id="password-2fa"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Confirm your password"
              />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
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
