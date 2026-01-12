import { ApiError } from '@/api/client';
import { User, UserUpdate } from '@/types/user';
import { useProjects } from '@/hooks/queries/use-projects';
import { useTeams } from '@/hooks/queries/use-teams';
import { 
  useUpdateUser, 
  useAdminMigrateUser, 
  useAdminResetPassword, 
  useAdminDisable2FA 
} from '@/hooks/queries/use-users';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Shield, Users as UsersIcon, Folder, KeyRound, RefreshCw } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useNavigate } from 'react-router-dom';
import { toast } from "sonner"
import { useAuth } from '@/context/useAuth';
import { useState } from 'react';
import { UserPermissionsDialog } from './UserPermissionsDialog';

interface UserDetailsDialogProps {
  user: User | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function UserDetailsDialog({ user, open, onOpenChange }: UserDetailsDialogProps) {
  const { hasPermission } = useAuth();
  const navigate = useNavigate();
  const [isPermissionDialogOpen, setIsPermissionDialogOpen] = useState(false);
  const [resetLink, setResetLink] = useState<string | null>(null);

  const { data: projectsData, isLoading: isLoadingProjects, error: errorProjects } = useProjects('', 1, 100);

  const projects = projectsData?.items || [];

  const { data: teams, isLoading: isLoadingTeams, error: errorTeams } = useTeams();

  const updateUserMutation = useUpdateUser();
  const migrateUserMutation = useAdminMigrateUser();
  const resetPasswordMutation = useAdminResetPassword();
  const disable2FAMutation = useAdminDisable2FA();

  // Helper to handle mutation executions with toasts
  const handleUpdate = (id: string, data: UserUpdate) => {
    updateUserMutation.mutate({ id, data }, {
        onSuccess: () => {
             toast.success("Success", { description: "User updated successfully." });
        },
        onError: (error) => {
             toast.error("Error", { description: (error as ApiError).response?.data?.detail || "Failed to update user." });
        }
    });
  };

  const handleMigrate = (userId: string) => {
      migrateUserMutation.mutate(userId, {
          onSuccess: () => {
              toast.success("User Migrated", { description: "User authentication provider set to 'local'. You can now reset their password." });
          },
          onError: (error) => {
              toast.error("Migration Failed", { description: (error as ApiError).response?.data?.detail || "Failed to migrate user." });
          }
      });
  };

  const handleResetPassword = (userId: string) => {
      resetPasswordMutation.mutate(userId, {
          onSuccess: (data: { email_sent?: boolean; reset_link?: string }) => {
            if (data.email_sent) {
                toast.success("Password Reset Initiated", { description: "An email with the reset link has been sent to the user." });
            } else {
                toast.success("Password Reset Initiated", { description: "Email not configured. Please share the link manually." });
            }
            setResetLink(data.reset_link || null);
          },
          onError: (error) => {
              toast.error("Reset Failed", { description: (error as ApiError).response?.data?.detail || "Failed to initiate password reset." });
          }
      });
  };

  const handleDisable2FA = (userId: string) => {
      disable2FAMutation.mutate(userId, {
          onSuccess: () => {
              toast.success("2FA Disabled", { description: "Two-Factor Authentication has been disabled for this user." });
          },
          onError: (error) => {
              toast.error("Action Failed", { description: (error as ApiError).response?.data?.detail || "Failed to disable 2FA." });
          }
      });
  };

  const handleToggleStatus = () => {
    if (!user) return;
    const newStatus = !user.is_active;
    handleUpdate(user._id || user.id, { is_active: newStatus });
  };

  const getUserProjects = (userId: string) => {
    if (!projects) return [];
    
    // Find teams this user belongs to
    const userTeamIds = teams 
      ? teams.filter(t => t.members?.some(m => m.user_id === userId)).map(t => t._id)
      : [];

    return projects.filter(p => 
      p.owner_id === userId || 
      p.members?.some(m => m.user_id === userId) ||
      (p.team_id && userTeamIds.includes(p.team_id))
    );
  };
  
  const getUserTeams = (userId: string) => {
    if (!teams) return [];
    return teams.filter(t => t.members?.some(m => m.user_id === userId));
  };

  return (
    <>
      <Dialog open={open} onOpenChange={(val) => {
        if (!val) setResetLink(null);
        onOpenChange(val);
      }}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>User Details: {user?.username}</DialogTitle>
          </DialogHeader>
          
          {user && (
            <div className="grid gap-6 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Email</Label>
                  <div className="text-sm font-medium">{user.email}</div>
                </div>
                <div>
                  <Label>Auth Provider</Label>
                  <div className="text-sm font-medium capitalize">{user.auth_provider || 'local'}</div>
                </div>
                <div>
                  <Label>Status</Label>
                  <div className="flex items-center gap-2">
                    {user.is_active ? (
                        <span className="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                          Inactive
                        </span>
                      )}
                      {hasPermission('user:update') && (
                        <Button 
                          variant="outline" 
                          size="sm" 
                          className="h-6 text-xs ml-2"
                          onClick={handleToggleStatus}
                        >
                          {user.is_active ? "Deactivate" : "Activate"}
                        </Button>
                      )}
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                    <h3 className="text-lg font-medium flex items-center gap-2">
                    <Shield className="h-5 w-5" /> Permissions
                    </h3>
                    {hasPermission('user:update') && (
                      <Button variant="outline" size="sm" onClick={() => setIsPermissionDialogOpen(true)}>
                          Manage Permissions
                      </Button>
                    )}
                </div>
                <div className="flex flex-wrap gap-1">
                    {user.permissions.length === 0 && <span className="text-sm text-muted-foreground">No permissions assigned.</span>}
                    {user.permissions.includes('*') && (
                        <span className="inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-primary text-primary-foreground hover:bg-primary/80">
                            Administrator
                        </span>
                    )}
                    {user.permissions.filter(p => p !== '*').slice(0, 5).map(p => (
                        <span key={p} className="inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                            {p}
                        </span>
                    ))}
                    {user.permissions.filter(p => p !== '*').length > 5 && (
                        <span className="text-xs text-muted-foreground flex items-center">
                            +{user.permissions.filter(p => p !== '*').length - 5} more
                        </span>
                    )}
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-lg font-medium flex items-center gap-2">
                  <KeyRound className="h-5 w-5" /> Security & Authentication
                </h3>
                <div className="border rounded-md p-4 space-y-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <div className="text-sm font-medium">Authentication Provider</div>
                            <div className="text-sm text-muted-foreground capitalize">{user.auth_provider || 'local'}</div>
                        </div>
                        {hasPermission('user:update') && user.auth_provider !== 'local' && (
                            <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={() => handleMigrate(user._id || user.id)}
                                disabled={migrateUserMutation.isPending}
                            >
                                {migrateUserMutation.isPending ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                                Migrate to Local
                            </Button>
                        )}
                    </div>

                    {user.auth_provider === 'local' && hasPermission('user:update') && (
                        <div className="flex items-center justify-between pt-2 border-t">
                            <div>
                                <div className="text-sm font-medium">Password Reset</div>
                                <div className="text-sm text-muted-foreground">Send a password reset email to the user.</div>
                            </div>
                            <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={() => handleResetPassword(user._id || user.id)}
                                disabled={resetPasswordMutation.isPending}
                            >
                                {resetPasswordMutation.isPending ? "Sending..." : "Send Reset Email"}
                            </Button>
                        </div>
                    )}

                    {resetLink && (
                        <div className="bg-muted p-3 rounded-md text-sm break-all">
                            <div className="font-medium mb-1">Reset Link (Manual):</div>
                            {resetLink}
                        </div>
                    )}

                    {user.totp_enabled && hasPermission('user:update') && (
                        <div className="flex items-center justify-between pt-2 border-t">
                            <div>
                                <div className="text-sm font-medium">Two-Factor Authentication</div>
                                <div className="text-sm text-muted-foreground">User has 2FA enabled.</div>
                            </div>
                            <Button 
                                variant="destructive" 
                                size="sm" 
                                onClick={() => handleDisable2FA(user._id || user.id)}
                                disabled={disable2FAMutation.isPending}
                            >
                                {disable2FAMutation.isPending ? "Disabling..." : "Disable 2FA"}
                            </Button>
                        </div>
                    )}
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-lg font-medium flex items-center gap-2">
                  <Folder className="h-5 w-5" /> Projects
                </h3>
                <div className="border rounded-md p-4">
                  {isLoadingProjects ? (
                    <div className="space-y-2">
                      <Skeleton className="h-8 w-full" />
                      <Skeleton className="h-8 w-full" />
                      <Skeleton className="h-8 w-full" />
                    </div>
                  ) : errorProjects ? (
                    <div className="text-sm text-destructive">Failed to load projects.</div>
                  ) : getUserProjects(user._id || user.id).length > 0 ? (
                    <ul className="space-y-2 max-h-60 overflow-y-auto pr-2">
                      {getUserProjects(user._id || user.id).map(project => (
                        <li 
                          key={project._id} 
                          className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 cursor-pointer transition-colors"
                          onClick={() => navigate(`/projects/${project._id}`)}
                        >
                          <span>{project.name}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="text-sm text-muted-foreground">No projects found.</div>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-lg font-medium flex items-center gap-2">
                  <UsersIcon className="h-5 w-5" /> Teams
                </h3>
                <div className="border rounded-md p-4">
                  {isLoadingTeams ? (
                    <div className="space-y-2">
                      <Skeleton className="h-8 w-full" />
                      <Skeleton className="h-8 w-full" />
                    </div>
                  ) : errorTeams ? (
                    <div className="text-sm text-destructive">Failed to load teams.</div>
                  ) : getUserTeams(user._id || user.id).length > 0 ? (
                    <ul className="space-y-2 max-h-60 overflow-y-auto pr-2">
                      {getUserTeams(user._id || user.id).map(team => (
                        <li 
                          key={team._id} 
                          className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 cursor-pointer transition-colors"
                          onClick={() => navigate('/teams')}
                        >
                          <span>{team.name}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="text-sm text-muted-foreground">No teams found.</div>
                  )}
                </div>
              </div>

            </div>
          )}
        </DialogContent>
      </Dialog>

      <UserPermissionsDialog 
        key={user?._id || user?.id}
        user={user} 
        open={isPermissionDialogOpen} 
        onOpenChange={setIsPermissionDialogOpen} 
      />
    </>
  );
}
