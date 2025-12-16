import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getUsers, getPendingInvitations, User } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { InviteUserDialog } from '@/components/users/InviteUserDialog';
import { UserTable } from '@/components/users/UserTable';
import { UserDetailsDialog } from '@/components/users/UserDetailsDialog';
import { Input } from '@/components/ui/input';
import { Search } from 'lucide-react';
import { useDebounce } from '@/hooks/use-debounce'; // Assuming we have this or I'll implement a simple debounce

export default function UsersPage() {
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("username");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");
  const debouncedSearch = useDebounce(search, 500);
  const limit = 20;
  
  const { hasPermission } = useAuth();

  const { data: users, isLoading: isLoadingUsers, error } = useQuery({
    queryKey: ['users', page, debouncedSearch, sortBy, sortOrder],
    queryFn: () => getUsers(page * limit, limit, debouncedSearch, sortBy, sortOrder),
  });

  const { data: invitations, isLoading: isLoadingInvitations } = useQuery({
    queryKey: ['invitations'],
    queryFn: getPendingInvitations,
  });

  const isLoading = isLoadingUsers || isLoadingInvitations;

  const filteredInvitations = invitations?.filter(invite => 
    !debouncedSearch || invite.email.toLowerCase().includes(debouncedSearch.toLowerCase())
  ) || [];

  const allUsers: User[] = [
    ...filteredInvitations.map(invite => ({
      id: invite._id,
      email: invite.email,
      username: invite.email,
      is_active: false,
      permissions: [],
      totp_enabled: false,
      status: 'invited' as const
    })),
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
        <div className="flex gap-2 items-center">
          <div className="relative w-64">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search users..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
          </div>
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
            sortBy={sortBy}
            sortOrder={sortOrder}
            onSort={(column) => {
              if (sortBy === column) {
                setSortOrder(sortOrder === "asc" ? "desc" : "asc");
              } else {
                setSortBy(column);
                setSortOrder("asc");
              }
            }}
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
