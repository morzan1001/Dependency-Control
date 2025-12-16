import { User, deleteUser, inviteUser } from '@/lib/api';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Check, X, Trash2, ChevronLeft, ChevronRight } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { toast } from "sonner"
import { useAuth } from '@/context/AuthContext';
import { useState } from 'react';
import { AxiosError } from 'axios';

interface UserTableProps {
  users: User[] | undefined;
  page: number;
  limit: number;
  onPageChange: (page: number) => void;
  onSelectUser: (user: User) => void;
}

export function UserTable({ users, page, limit, onPageChange, onSelectUser }: UserTableProps) {
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);

  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) => deleteUser(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsDeleteDialogOpen(false);
      setUserToDelete(null);
      toast.success("User deleted successfully");
    },
    onError: (error: AxiosError<any>) => {
      toast.error("Failed to delete user", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  });

  const resendInviteMutation = useMutation({
    mutationFn: (email: string) => inviteUser(email),
    onSuccess: () => {
      toast.success("Invitation resent successfully");
    },
    onError: (error: AxiosError<any>) => {
      toast.error("Failed to resend invitation", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  });

  return (
    <>
      <div className="relative w-full overflow-auto">
        <table className="w-full caption-bottom text-sm">
          <thead className="[&_tr]:border-b">
            <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Username</th>
              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Email</th>
              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Status</th>
              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">2FA</th>
              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Permissions</th>
              <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Actions</th>
            </tr>
          </thead>
          <tbody className="[&_tr:last-child]:border-0">
            {users?.map((user: User) => (
              <tr 
                key={user._id || user.id} 
                className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer"
                onClick={() => onSelectUser(user)}
              >
                <td className="p-4 align-middle font-medium">
                  <div className="flex items-center gap-2">
                    {user.username}
                    {user.auth_provider && user.auth_provider !== 'local' && (
                      <span className="inline-flex items-center rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800 capitalize">
                        {user.auth_provider}
                      </span>
                    )}
                  </div>
                </td>
                <td className="p-4 align-middle">{user.email}</td>
                <td className="p-4 align-middle">
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
                </td>
                <td className="p-4 align-middle">
                    {user.totp_enabled ? (
                        <Check className="h-4 w-4 text-green-500" />
                    ) : (
                        <X className="h-4 w-4 text-red-500" />
                    )}
                </td>
                <td className="p-4 align-middle">
                  <div className="flex gap-1 flex-wrap">
                    {user.permissions.map((perm) => (
                      <span key={perm} className="inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                        {perm}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="p-4 align-middle" onClick={(e) => e.stopPropagation()}>
                  <div className="flex items-center gap-2">
                    {user.status === 'invited' && hasPermission('user:manage') && (
                       <Button 
                         variant="outline" 
                         size="sm"
                         onClick={(e: React.MouseEvent) => {
                           e.stopPropagation();
                           resendInviteMutation.mutate(user.email);
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
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
                onClick={() => userToDelete && deleteUserMutation.mutate(userToDelete._id || userToDelete.id)}
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
