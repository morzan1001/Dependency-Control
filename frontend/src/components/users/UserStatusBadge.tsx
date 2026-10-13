import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import type { User } from '@/types/user';

const TONES = {
  yellow: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-200',
  green: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-200',
  red: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-200',
};

export function StatusPill({ tone, children }: Readonly<{ tone: keyof typeof TONES; children: ReactNode }>) {
  return (
    <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium', TONES[tone])}>
      {children}
    </span>
  );
}

export function UserStatusBadge({ user }: Readonly<{ user: Pick<User, 'is_active' | 'status'> }>) {
  if (user.status === 'invited') return <StatusPill tone="yellow">Invited</StatusPill>;
  return user.is_active ? <StatusPill tone="green">Active</StatusPill> : <StatusPill tone="red">Inactive</StatusPill>;
}
