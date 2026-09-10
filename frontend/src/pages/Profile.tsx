import { useCurrentUser } from '@/hooks/queries/use-users';
import { useNotificationChannels, useAppConfig } from '@/hooks/queries/use-system';
import { Skeleton } from '@/components/ui/skeleton';
import { UserDetailsCard } from '@/components/profile/UserDetailsCard';
import { PasswordUpdateCard } from '@/components/profile/PasswordUpdateCard';
import { TwoFactorAuthCard } from '@/components/profile/TwoFactorAuthCard';
import { NotificationPreferencesCard } from '@/components/profile/NotificationPreferencesCard';
import { ApiKeysCard } from '@/components/profile/ApiKeysCard';
import { MCPApiKeysCard } from '@/components/profile/MCPApiKeysCard';
import { AdhocApiKeysCard } from '@/components/profile/AdhocApiKeysCard';
import { useAuth } from '@/context';
import { Permissions } from '@/lib/permissions';

export default function ProfilePage() {
  const { data: user, isLoading } = useCurrentUser();
  const { hasPermission } = useAuth();
  const canUseMcp = hasPermission(Permissions.MCP_ACCESS);
  const canUseAdhocAnalysis = hasPermission(Permissions.ANALYZE_ADHOC);

  const { data: notificationChannels } = useNotificationChannels();
  const { data: appConfig } = useAppConfig();

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-4xl">
        <Skeleton className="h-10 w-32" />
        <div className="grid gap-6 md:grid-cols-2">
          <Skeleton className="h-64 rounded-xl" />
          <Skeleton className="h-64 rounded-xl" />
          <Skeleton className="h-64 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-3xl font-bold tracking-tight">Profile</h1>

      <div className="grid gap-6 md:grid-cols-2">
        <UserDetailsCard key={user?.id} user={user} notificationChannels={notificationChannels} appConfig={appConfig} />
        <div className="space-y-6">
          <PasswordUpdateCard user={user} />
          <TwoFactorAuthCard user={user} />
        </div>
      </div>

      <NotificationPreferencesCard key={`notif-${user?.id}`} user={user} availableChannels={notificationChannels} />

      {/* Ownership alone decides listing and revoking, so a key stays reachable after a permission goes. */}
      <ApiKeysCard />

      {(canUseMcp || canUseAdhocAnalysis) && (
        <p className="text-sm text-muted-foreground">
          The per-surface cards below are superseded: their keys still work, and replacing them with a
          key from the card above lets you retire them.
        </p>
      )}
      {canUseMcp && <MCPApiKeysCard />}
      {canUseAdhocAnalysis && <AdhocApiKeysCard />}
    </div>
  );
}
