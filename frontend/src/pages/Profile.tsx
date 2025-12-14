import { useQuery } from '@tanstack/react-query';
import { getMe, getSystemSettings } from '@/lib/api';
import { Skeleton } from '@/components/ui/skeleton';
import { UserDetailsCard } from '@/components/profile/UserDetailsCard';
import { PasswordUpdateCard } from '@/components/profile/PasswordUpdateCard';
import { TwoFactorAuthCard } from '@/components/profile/TwoFactorAuthCard';

export default function ProfilePage() {
  const { data: user, isLoading } = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
  });

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

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
        <UserDetailsCard user={user} systemSettings={systemSettings} />
        <div className="space-y-6">
          <PasswordUpdateCard user={user} />
          <TwoFactorAuthCard user={user} />
        </div>
      </div>
    </div>
  );
}
