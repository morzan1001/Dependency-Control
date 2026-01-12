import { ApiError } from '@/api/client';
import { User } from '@/types/user';
import { useDeleteUser, useInviteUser } from '@/hooks/queries/use-users';
import { Button } from '@/components/ui/button';
import { Check, X, Trash2, ArrowUp, ArrowDown, ChevronLeft, ChevronRight } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { toast } from "sonner"
import { useAuth } from '@/context/useAuth';
import { useState } from 'react';

interface UserTableProps {
  users: User[] | undefined;
  page: number;
  limit: number;
  onPageChange: (page: number) => void;
  onSelectUser: (user: User) => void;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
  onSort?: (column: string) => void;
}

export function UserTable({ users, page, limit, onPageChange, onSelectUser, sortBy, sortOrder, onSort }: UserTableProps) {
  const { hasPermission } = useAuth();
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);

  const deleteUserMutation = useDeleteUser();
  const resendInviteMutation = useInviteUser();
  
  const handleDeleteUser = (userId: string) => {
      deleteUserMutation.mutate(userId, {
        onSuccess: () => {
          setIsDeleteDialogOpen(false);
          setUserToDelete(null);
          toast.success("User deleted successfully");
        },
        onError: (error) => {
          toast.error("Failed to delete user", {
            description: (error as ApiError).response?.data?.detail || "An error occurred"
          })
        }
      });
  }

  const handleResendInvite = (email: string) => {
      resendInviteMutation.mutate(email, {
        onSuccess: () => {
          toast.success("Invitation resent successfully");
        },
        onError: (error) => {
          toast.error("Failed to resend invitation", {
            description: (error as ApiError).response?.data?.detail || "An error occurred"
          })
        }
      });
  }

  const renderSortIcon = (column: string) => {
    if (sortBy === column) {
      return sortOrder === 'asc' ? <ArrowUp className="ml-2 h-4 w-4 inline" /> : <ArrowDown className="ml-2 h-4 w-4 inline" />;
    }
    return null;
  };

  const handleSort = (column: string) => {
    if (onSort) {
      onSort(column);
    }
  };

  return (
    <>
      <div className="relative w-full overflow-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('username')}>
                <div className="flex items-center">
                  Username
                  {renderSortIcon('username')}
                </div>
              </TableHead>
              <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('email')}>
                <div className="flex items-center">
                  Email
                  {renderSortIcon('email')}
                </div>
              </TableHead>
              <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('status')}>
                <div className="flex items-center">
                  Status
                  {renderSortIcon('status')}
                </div>
              </TableHead>
              <TableHead>2FA</TableHead>
              <TableHead>Permissions</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users?.map((user: User) => (
              <TableRow 
                key={user._id || user.id} 
                className="cursor-pointer"
                onClick={() => onSelectUser(user)}
              >
                <TableCell className="font-medium">
                  <div className="flex items-center gap-2">
                    {user.username}
                    {user.auth_provider && user.auth_provider !== 'local' && (
                      <span className="inline-flex items-center rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800 capitalize">
                        {user.auth_provider}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>
                  {user.status === 'invited' ? (
                    <span className="inline-flex items-center rounded-full bg-yellow-100 px-2.5 py-0.5 text-xs font-medium text-yellow-800">
                      Invited
                    </span>
                  ) : user.is_active ? (
                    <span className="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                      Inactive
                    </span>
                  )}
                </TableCell>
                <TableCell>
                    {user.totp_enabled ? (
                        <Check className="h-4 w-4 text-green-500" />
                    ) : (
                        <X className="h-4 w-4 text-red-500" />
                    )}
                </TableCell>
                <TableCell>
                  <div className="flex gap-1 flex-wrap">
                    {user.permissions.map((perm) => (
                      <span key={perm} className="inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                        {perm}
                      </span>
                    ))}
                  </div>
                </TableCell>
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <div className="flex items-center gap-2">
                    {user.status === 'invited' && hasPermission('user:manage') && (
                       <Button 
                         variant="outline" 
                         size="sm"
                         onClick={(e: React.MouseEvent) => {
                           e.stopPropagation();
                           handleResendInvite(user.email);
                         }}
                         disabled={resendInviteMutation.isPending}
                       >
                         {resendInviteMutation.isPending ? "Sending..." : "Resend"}
                       </Button>
                    )}
                    {hasPermission('user:delete') && (
                      <Button 
                          variant="ghost" 
                          size="icon" 
                          className="text-destructive hover:text-destructive/90"
                          onClick={() => {
                              setUserToDelete(user);
                              setIsDeleteDialogOpen(true);
                          }}
                      >
                          <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {!(page === 0 && (!users || users.length < limit)) && (
        <div className="flex items-center justify-end space-x-2 py-4">
          {page > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => onPageChange(Math.max(0, page - 1))}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
          )}
          {users && users.length >= limit && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => onPageChange(page + 1)}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      )}

      <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete User</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete user {userToDelete?.username}? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDeleteDialogOpen(false)}>Cancel</Button>
            <Button 
                variant="destructive" 
                onClick={() => userToDelete && handleDeleteUser(userToDelete._id || userToDelete.id)}
                disabled={deleteUserMutation.isPending}
            >
              {deleteUserMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
