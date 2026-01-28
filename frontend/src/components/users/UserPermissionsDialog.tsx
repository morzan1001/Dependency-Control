import { User } from '@/types/user';
import { getErrorMessage } from '@/lib/utils';
import { useUpdateUser } from '@/hooks/queries/use-users';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import {
  PERMISSION_GROUPS,
  PRESET_ADMIN,
  PRESET_USER,
  PRESET_VIEWER
} from '@/lib/permissions';
import { toast } from "sonner"
import { Shield, User as UserIcon, Eye, X } from 'lucide-react';

interface UserPermissionsDialogProps {
  user: User | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function UserPermissionsDialog({ user, open, onOpenChange }: UserPermissionsDialogProps) {
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>(user?.permissions || []);

  const updateUserMutation = useUpdateUser();

  // Sync selectedPermissions when user changes or dialog opens
  useEffect(() => {
    if (user) {
      setSelectedPermissions(user.permissions || []);
    }
  }, [user, open]);

  const handlePermissionChange = (permission: string, checked: boolean) => {
    if (checked) {
      setSelectedPermissions(prev => [...prev, permission]);
    } else {
      setSelectedPermissions(prev => prev.filter(p => p !== permission));
    }
  };

  const handleSelectPreset = (preset: string[]) => {
    setSelectedPermissions([...preset]);
  };

  const handleClearAll = () => {
    setSelectedPermissions([]);
  };

  const handleSelectGroupAll = (groupPermissions: string[], select: boolean) => {
    if (select) {
      setSelectedPermissions(prev => {
        const newPerms = new Set(prev);
        groupPermissions.forEach(p => newPerms.add(p));
        return [...newPerms];
      });
    } else {
      setSelectedPermissions(prev => prev.filter(p => !groupPermissions.includes(p)));
    }
  };

  const isGroupFullySelected = (groupPermissions: string[]) => {
    return groupPermissions.every(p => selectedPermissions.includes(p));
  };

  const handleSave = () => {
    if (!user) return;
    updateUserMutation.mutate({
      id: user.id,
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
          description: getErrorMessage(error),
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
              {/* Preset Buttons */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Quick Presets</Label>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleSelectPreset(PRESET_ADMIN)}
                    className="gap-1.5"
                  >
                    <Shield className="h-3.5 w-3.5" />
                    All Permissions
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleSelectPreset(PRESET_USER)}
                    className="gap-1.5"
                  >
                    <UserIcon className="h-3.5 w-3.5" />
                    Standard User
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleSelectPreset(PRESET_VIEWER)}
                    className="gap-1.5"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    Viewer
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleClearAll}
                    className="gap-1.5"
                  >
                    <X className="h-3.5 w-3.5" />
                    Clear All
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Selected: {selectedPermissions.length} permission{selectedPermissions.length !== 1 ? 's' : ''}
                </p>
              </div>

              {/* Permission Groups */}
              {PERMISSION_GROUPS.map((group) => {
                  const groupPermIds = group.permissions.map(p => p.id);
                  const allSelected = isGroupFullySelected(groupPermIds);
                  return (
                  <div key={group.title} className="space-y-3">
                      <div className="flex items-center justify-between border-b pb-1">
                        <h4 className="font-medium text-sm text-muted-foreground">{group.title}</h4>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 text-xs"
                          onClick={() => handleSelectGroupAll(groupPermIds, !allSelected)}
                        >
                          {allSelected ? 'Deselect All' : 'Select All'}
                        </Button>
                      </div>
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
                  );
              })}
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
