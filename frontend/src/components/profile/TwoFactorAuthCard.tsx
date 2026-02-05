import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { authApi } from '@/api/auth';
import { ApiError } from '@/api/client';
import { User, TwoFASetup } from '@/types/user';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Shield, ShieldAlert, KeyRound } from 'lucide-react';
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

  const handleSetupClose = () => {
    setIsSetupOpen(false);
    // Clear sensitive data when dialog closes
    setSetupData(null);
  };

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

  // Check if user authenticates via external provider (OIDC)
  const isOidcUser = user?.auth_provider && user.auth_provider !== 'local';

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Two-Factor Authentication</CardTitle>
          <CardDescription>Manage your 2FA settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isOidcUser ? (
            // OIDC users cannot configure local 2FA
            <div className="flex items-center justify-between p-4 border rounded-lg bg-muted/50">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-full">
                  <KeyRound className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <div className="font-medium">External Authentication</div>
                  <div className="text-sm text-muted-foreground">
                    You are signed in via <span className="font-medium capitalize">{user.auth_provider}</span>.
                    <br />
                    Please configure 2FA in your identity provider.
                  </div>
                </div>
              </div>
              <span className="inline-flex items-center rounded-full bg-blue-100 dark:bg-blue-900/30 px-3 py-1 text-sm font-medium text-blue-800 dark:text-blue-200 capitalize">
                {user.auth_provider}
              </span>
            </div>
          ) : (
            // Local users can configure 2FA
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex items-center gap-3">
                {user?.totp_enabled ? (
                  <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-full">
                    <Shield className="h-6 w-6 text-success" />
                  </div>
                ) : (
                  <div className="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-full">
                    <ShieldAlert className="h-6 w-6 text-warning" />
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
          )}
        </CardContent>
      </Card>

      <TwoFASetupDialog
        setupData={setupData}
        isOpen={isSetupOpen}
        onClose={handleSetupClose}
      />

      <TwoFADisableDialog 
        isOpen={isDisableOpen} 
        onClose={() => setIsDisableOpen(false)} 
      />
    </>
  );
}
