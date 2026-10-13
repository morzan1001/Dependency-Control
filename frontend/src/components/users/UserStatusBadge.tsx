import { cn } from '@/lib/utils';
import type { User } from '@/types/user';

const TONES = {
  Invited: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-200',
  Active: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-200',
  Inactive: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-200',
};

export function UserStatusBadge({ user }: Readonly<{ user: Pick<User, 'is_active' | 'status'> }>) {
  const active = user.is_active ? 'Active' : 'Inactive';
  const status = user.status === 'invited' ? 'Invited' : active;
  return (
    <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium', TONES[status])}>
      {status}
    </span>
  );
}
