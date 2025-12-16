import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getUsers, getPendingInvitations, User } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { InviteUserDialog } from '@/components/users/InviteUserDialog';
import { UserTable } from '@/components/users/UserTable';
import { UserDetailsDialog } from '@/components/users/UserDetailsDialog';

export default function UsersPage() {
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [page, setPage] = useState(0);
  const limit = 20;
  
  const { hasPermission } = useAuth();

  const { data: users, isLoading: isLoadingUsers } = useQuery({
    queryKey: ['users', page],
    queryFn: () => getUsers(page * limit, limit),
  });

  const { data: invitations, isLoading: isLoadingInvitations } = useQuery({
    queryKey: ['invitations'],
    queryFn: getPendingInvitations,
  });

  const isLoading = isLoadingUsers || isLoadingInvitations;

  const allUsers: User[] = [
    ...(invitations?.map(invite => ({
      id: invite._id,
      email: invite.email,
      username: invite.email,
      is_active: false,
      permissions: [],
      totp_enabled: false,
      status: 'invited' as const
    })) || []),
    ...(users || []).map(u => ({ ...u, status: 'active' as const }))
  ];

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-10 w-32" />
        </div>
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-24" />
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <Skeleton className="h-12 w-full" />
              </div>
              <div className="flex items-center space-x-4">
                <Skeleton className="h-12 w-full" />
              </div>
              <div className="flex items-center space-x-4">
                <Skeleton className="h-12 w-full" />
              </div>
              <div className="flex items-center space-x-4">
                <Skeleton className="h-12 w-full" />
              </div>
              <div className="flex items-center space-x-4">
                <Skeleton className="h-12 w-full" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error) {
    return <div className="text-red-500">Error loading users</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Users</h1>
        <div className="flex gap-2">
          {hasPermission('user:create') && (
            <InviteUserDialog />
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Users</CardTitle>
        </CardHeader>
        <CardContent>
          <UserTable 
            users={allUsers} 
            page={page} 
            limit={limit} 
            onPageChange={setPage} 
            onSelectUser={setSelectedUser} 
          />
        </CardContent>
      </Card>

      <UserDetailsDialog 
        user={selectedUser} 
        open={!!selectedUser} 
        onOpenChange={(open) => !open && setSelectedUser(null)} 
      />
    </div>
  );
}
