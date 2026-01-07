import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { authApi } from '@/api/auth';
import { ApiError } from '@/api/client';
import { User, TwoFASetup } from '@/types/user';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Shield, ShieldAlert } from 'lucide-react';
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"
import { TwoFASetupDialog } from './TwoFASetupDialog';
import { TwoFADisableDialog } from './TwoFADisableDialog';

interface TwoFactorAuthCardProps {
  user: User | undefined;
}

export function TwoFactorAuthCard({ user }: TwoFactorAuthCardProps) {
  const [isSetupOpen, setIsSetupOpen] = useState(false);
  const [isDisableOpen, setIsDisableOpen] = useState(false);
  const [setupData, setSetupData] = useState<TwoFASetup | null>(null);

  const setup2FAMutation = useMutation({
    mutationFn: authApi.setup2FA,
    onSuccess: (data) => {
      setSetupData(data);
      setIsSetupOpen(true);
    },
    onError: (error: ApiError) => {
      toast.error("Error", {
        description: getErrorMessage(error),
      });
    }
  });

  return (
    <>
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
              <Button 
                variant="destructive" 
                onClick={() => setIsDisableOpen(true)}
              >
                Disable 2FA
              </Button>
            ) : (
              <Button 
                onClick={() => setup2FAMutation.mutate()}
                disabled={setup2FAMutation.isPending}
              >
                {setup2FAMutation.isPending ? 'Setting up...' : 'Enable 2FA'}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <TwoFASetupDialog 
        setupData={setupData} 
        isOpen={isSetupOpen} 
        onClose={() => setIsSetupOpen(false)} 
      />

      <TwoFADisableDialog 
        isOpen={isDisableOpen} 
        onClose={() => setIsDisableOpen(false)} 
      />
    </>
  );
}
