import { User, updateUser, UserUpdate } from '@/lib/api';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { PERMISSION_GROUPS } from '@/lib/constants';
import { toast } from "sonner"
import { AxiosError } from 'axios';

interface UserPermissionsDialogProps {
  user: User | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function UserPermissionsDialog({ user, open, onOpenChange }: UserPermissionsDialogProps) {
  const queryClient = useQueryClient();

  const updateUserMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UserUpdate }) => updateUser(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success("Success", {
        description: "User permissions updated successfully.",
      });
    },
    onError: (error: AxiosError<any>) => {
      toast.error("Error", {
        description: error.response?.data?.detail || "Failed to update user permissions.",
      });
    },
  });

  const handlePermissionChange = (permission: string, hasPermission: boolean) => {
    if (!user) return;
    
    let newPermissions = [...user.permissions];
    if (hasPermission) {
      if (!newPermissions.includes(permission)) {
        newPermissions.push(permission);
      }
    } else {
      newPermissions = newPermissions.filter(p => p !== permission);
    }
    
    updateUserMutation.mutate({
      id: user._id || user.id,
      data: { permissions: newPermissions }
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Manage Permissions for {user?.username}</DialogTitle>
          <DialogDescription>
              Select the permissions you want to assign to this user.
          </DialogDescription>
        </DialogHeader>
        
        {user && (
          <div className="grid gap-6 py-4">
              {PERMISSION_GROUPS.map((group) => (
                  <div key={group.title} className="space-y-3">
                      <h4 className="font-medium text-sm text-muted-foreground border-b pb-1">{group.title}</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                          {group.permissions.map((perm) => (
                              <div key={perm.id} className="flex items-start space-x-2">
                                  <Checkbox 
                                      id={`perm-dialog-${perm.id}`} 
                                      checked={user.permissions.includes(perm.id)}
                                      onCheckedChange={(checked: boolean) => handlePermissionChange(perm.id, checked)}
                                  />
                                  <div className="grid gap-1.5 leading-none">
                                      <Label htmlFor={`perm-dialog-${perm.id}`} className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                                          {perm.label}
                                      </Label>
                                      <p className="text-xs text-muted-foreground">
                                          {perm.description}
                                      </p>
                                  </div>
                              </div>
                          ))}
                      </div>
                  </div>
              ))}
          </div>
        )}
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
