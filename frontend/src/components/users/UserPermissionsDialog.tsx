import { ApiError } from '@/api/client';
import { User } from '@/types/user'; 
import { useUpdateUser } from '@/hooks/queries/use-users';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { useState } from 'react';
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

interface UserPermissionsDialogProps {
  user: User | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function UserPermissionsDialog({ user, open, onOpenChange }: UserPermissionsDialogProps) {
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>(user?.permissions || []);

  const updateUserMutation = useUpdateUser();

  const handlePermissionChange = (permission: string, checked: boolean) => {
    if (checked) {
      setSelectedPermissions(prev => [...prev, permission]);
    } else {
      setSelectedPermissions(prev => prev.filter(p => p !== permission));
    }
  };

  const handleSave = () => {
    if (!user) return;
    updateUserMutation.mutate({
      id: user._id || user.id,
      data: { permissions: selectedPermissions }
    }, {
      onSuccess: () => {
        toast.success("Success", {
          description: "User permissions updated successfully.",
        });
        onOpenChange(false);
      },
      onError: (error) => {
        toast.error("Error", {
          description: (error as ApiError).response?.data?.detail || "Failed to update user permissions.",
        });
      },
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
                                      checked={selectedPermissions.includes(perm.id)}
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
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={handleSave} disabled={updateUserMutation.isPending}>
            {updateUserMutation.isPending ? "Saving..." : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
