import { User } from '@/types/user';
import { useProjectsDropdown } from '@/hooks/queries/use-projects';
import { useTeams } from '@/hooks/queries/use-teams';
import {
  useUpdateUser,
  useAdminMigrateUser,
  useAdminResetPassword,
  useAdminDisable2FA
} from '@/hooks/queries/use-users';
import { Badge } from '@/components/ui/badge';
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
import { Link } from 'react-router-dom';
import { toast } from "sonner"
import { useAuth } from '@/context/useAuth';
import { useState } from 'react';
import { UserPermissionsDialog } from './UserPermissionsDialog';
import { RenameUserDialog } from './RenameUserDialog';
import { UserStatusBadge } from './UserStatusBadge';
import { ProjectOwner } from '@/components/project/ProjectOwner';
import { sharedNames } from '@/lib/utils';

interface AsyncListSectionProps {
  isLoading: boolean;
  error: unknown;
  emptyMessage: string;
  errorMessage: string;
  children: React.ReactNode;
  isEmpty: boolean;
  skeletonCount?: number;
}

function AsyncListSection({ isLoading, error, emptyMessage, errorMessage, children, isEmpty, skeletonCount = 3 }: Readonly<AsyncListSectionProps>) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: skeletonCount }, (_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    );
  }
  if (error) {
    return <div className="text-sm text-destructive">{errorMessage}</div>;
  }
  if (isEmpty) {
    return <div className="text-sm text-muted-foreground">{emptyMessage}</div>;
  }
  return <>{children}</>;
}

interface UserDetailsDialogProps {
  user: User | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUserUpdated?: (user: User) => void;
}

export function UserDetailsDialog({ user, open, onOpenChange, onUserUpdated }: Readonly<UserDetailsDialogProps>) {
  const { hasPermission } = useAuth();

  const [isPermissionDialogOpen, setIsPermissionDialogOpen] = useState(false);
  const [isRenameDialogOpen, setIsRenameDialogOpen] = useState(false);

  // Fetch all projects (paged) so membership isn't truncated in large orgs.
  const { data: projectsData, isLoading: isLoadingProjects, error: errorProjects } = useProjectsDropdown({ enabled: open });

  const projects = projectsData?.items || [];

  const { data: teams, isLoading: isLoadingTeams, error: errorTeams } = useTeams(undefined, undefined, undefined, { enabled: open });

  const updateUserMutation = useUpdateUser({
    errorTitle: user?.is_active ? "Failed to deactivate user" : "Failed to activate user",
  });
  const migrateUserMutation = useAdminMigrateUser({ errorTitle: "Failed to migrate user" });
  const resetPasswordMutation = useAdminResetPassword({ errorTitle: "Failed to send reset email" });
  const disable2FAMutation = useAdminDisable2FA({ errorTitle: "Failed to disable 2FA" });

  const handleMigrate = (userId: string) => {
      migrateUserMutation.mutate(userId, {
          onSuccess: (migrated) => {
              onUserUpdated?.(migrated);
              toast.success("User migrated", { description: "User authentication provider set to 'local'. You can now reset their password." });
          },
      });
  };

  const handleResetPassword = (userId: string) => {
      resetPasswordMutation.mutate(userId, {
          onSuccess: ({ email_queued }) => {
            if (email_queued) {
              toast.success("Password Reset Initiated", { description: "A reset email has been queued for the user." });
            } else {
              toast.error("Failed to send reset email", { description: "No reset email could be queued for the user" });
            }
          },
      });
  };

  const handleDisable2FA = (userId: string) => {
      disable2FAMutation.mutate(userId, {
          onSuccess: (updated) => {
              onUserUpdated?.(updated);
              toast.success("2FA disabled", { description: "Two-Factor Authentication has been disabled for this user." });
          },
      });
  };

  const handleToggleStatus = () => {
    if (!user) return;
    const activates = !user.is_active;
    updateUserMutation.mutate({ id: user.id, data: { is_active: activates } }, {
      onSuccess: (updated) => {
        onUserUpdated?.(updated);
        toast.success(activates ? "User activated" : "User deactivated");
      },
    });
  };

  const getUserProjects = (userId: string) => {
    if (!projects) return [];

    const userTeamIds = teams
      ? teams.filter(t => t.members?.some(m => m.user_id === userId)).map(t => t.id)
      : [];

    return projects.filter(p =>
      p.members?.some(m => m.user_id === userId) ||
      p.team_ids?.some(id => userTeamIds.includes(id))
    );
  };

  const getUserTeams = (userId: string) => {
    if (!teams) return [];
    return teams.filter(t => t.members?.some(m => m.user_id === userId));
  };

  const canUpdateUser = hasPermission('user:update');
  const userProjects = user ? getUserProjects(user.id) : [];
  const namesakes = sharedNames(userProjects);
  const userTeams = user ? getUserTeams(user.id) : [];
  const isLocalAuth = user?.auth_provider === 'local';

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="wrap-anywhere">User Details: {user?.username}</DialogTitle>
          </DialogHeader>
          
          {user && (
            <div className="grid gap-6 py-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <Label>Username</Label>
                  <div className="flex items-center gap-2">
                    <span className="wrap-anywhere text-sm font-medium">{user.username}</span>
                    {canUpdateUser && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-6 text-xs ml-2"
                        onClick={() => setIsRenameDialogOpen(true)}
                      >
                        Rename
                      </Button>
                    )}
                  </div>
                </div>
                <div>
                  <Label>Email</Label>
                  <div className="wrap-anywhere text-sm font-medium">{user.email}</div>
                </div>
                <div>
                  <Label>Auth Provider</Label>
                  <div className="text-sm font-medium capitalize">{user.auth_provider || 'local'}</div>
                </div>
                <div>
                  <Label>Status</Label>
                  <div className="flex items-center gap-2">
                      <UserStatusBadge user={user} />
                      {canUpdateUser && (
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
                    {canUpdateUser && (
                      <Button variant="outline" size="sm" onClick={() => setIsPermissionDialogOpen(true)}>
                          Manage Permissions
                      </Button>
                    )}
                </div>
                <div className="flex flex-wrap gap-1">
                    {user.permissions.length === 0 && <span className="text-sm text-muted-foreground">No permissions assigned.</span>}
                    {user.permissions.slice(0, 5).map(p => (
                        <Badge key={p} variant="secondary" className="rounded-md">
                            {p}
                        </Badge>
                    ))}
                    {user.permissions.length > 5 && (
                        <span className="text-xs text-muted-foreground flex items-center">
                            +{user.permissions.length - 5} more
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
                        {canUpdateUser && !isLocalAuth && (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleMigrate(user.id)}
                                disabled={migrateUserMutation.isPending}
                            >
                                {migrateUserMutation.isPending ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                                Migrate to Local
                            </Button>
                        )}
                    </div>

                    {isLocalAuth && canUpdateUser && (
                        <div className="flex items-center justify-between pt-2 border-t">
                            <div>
                                <div className="text-sm font-medium">Password Reset</div>
                                <div className="text-sm text-muted-foreground">Send a password reset email to the user.</div>
                            </div>
                            <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={() => handleResetPassword(user.id)}
                                disabled={resetPasswordMutation.isPending}
                            >
                                {resetPasswordMutation.isPending ? "Sending..." : "Send Reset Email"}
                            </Button>
                        </div>
                    )}

                    {user.totp_enabled && canUpdateUser && (
                        <div className="flex items-center justify-between pt-2 border-t">
                            <div>
                                <div className="text-sm font-medium">Two-Factor Authentication</div>
                                <div className="text-sm text-muted-foreground">User has 2FA enabled.</div>
                            </div>
                            <Button 
                                variant="destructive" 
                                size="sm" 
                                onClick={() => handleDisable2FA(user.id)}
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
                  <AsyncListSection
                    isLoading={isLoadingProjects}
                    error={errorProjects}
                    isEmpty={userProjects.length === 0}
                    errorMessage="Failed to load projects."
                    emptyMessage="No projects found."
                  >
                    <ul className="space-y-2 max-h-60 overflow-y-auto pr-2">
                      {userProjects.map(project => (
                        <li key={project.id}>
                          <Link
                            to={`/projects/${project.id}`}
                            className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 transition-colors"
                          >
                            <span className="flex min-w-0 items-center gap-2">
                              <span className="truncate">{project.name}</span>
                              {namesakes.has(project.name) && <ProjectOwner project={project} namesakes={namesakes.get(project.name)!} />}
                            </span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </AsyncListSection>
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-lg font-medium flex items-center gap-2">
                  <UsersIcon className="h-5 w-5" /> Teams
                </h3>
                <div className="border rounded-md p-4">
                  <AsyncListSection
                    isLoading={isLoadingTeams}
                    error={errorTeams}
                    isEmpty={userTeams.length === 0}
                    errorMessage="Failed to load teams."
                    emptyMessage="No teams found."
                    skeletonCount={2}
                  >
                    <ul className="space-y-2 max-h-60 overflow-y-auto pr-2">
                      {userTeams.map(team => (
                        <li key={team.id}>
                          <Link
                            to="/teams"
                            className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 transition-colors"
                          >
                            <span>{team.name}</span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </AsyncListSection>
                </div>
              </div>

            </div>
          )}
        </DialogContent>
      </Dialog>

      {isPermissionDialogOpen && (
        <UserPermissionsDialog user={user} onOpenChange={setIsPermissionDialogOpen} onUserUpdated={onUserUpdated} />
      )}

      {isRenameDialogOpen && user && (
        <RenameUserDialog user={user} onOpenChange={setIsRenameDialogOpen} onUserUpdated={onUserUpdated} />
      )}
    </>
  );
}
