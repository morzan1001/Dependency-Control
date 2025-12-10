import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getUsers, createUser, updateUser, deleteUser, inviteUser, getProjects, getTeams, User } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Plus, Check, X, Shield, Users as UsersIcon, Folder, Trash2, Mail, ChevronLeft, ChevronRight } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Link } from 'react-router-dom';
import { toast } from "sonner"
import { Spinner } from '@/components/ui/spinner';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// Grouped permissions
const PERMISSION_GROUPS = [
  {
    title: "System & Administration",
    permissions: [
      { id: "*", label: "Administrator", description: "Full access to all resources" },
      { id: "system:manage", label: "System Settings", description: "Manage system configurations" },
    ]
  },
  {
    title: "User Management",
    permissions: [
      { id: "user:read_all", label: "List All Users", description: "View list of all users in the system" },
      { id: "user:create", label: "Create Users", description: "Create new users" },
      { id: "user:read", label: "Read User Details", description: "View detailed user information" },
      { id: "user:update", label: "Update Users", description: "Update user profiles" },
      { id: "user:delete", label: "Delete Users", description: "Delete users" },
    ]
  },
  {
    title: "Team Management",
    permissions: [
      { id: "team:read_all", label: "Read All Teams", description: "View all teams in the system" },
      { id: "team:read", label: "Read Own Teams", description: "View teams you are a member of" },
      { id: "team:create", label: "Create Teams", description: "Create new teams" },
      { id: "team:update", label: "Update Teams", description: "Update any team" },
      { id: "team:delete", label: "Delete Teams", description: "Delete any team" },
    ]
  },
  {
    title: "Project Management",
    permissions: [
      { id: "project:read_all", label: "Read All Projects", description: "View all projects in the system" },
      { id: "project:read", label: "Read Own Projects", description: "View projects you are a member of" },
      { id: "project:create", label: "Create Projects", description: "Create new projects" },
      { id: "project:update", label: "Update Projects", description: "Update any project" },
    ]
  },
  {
    title: "Security & Compliance",
    permissions: [
      { id: "waiver:read_all", label: "Read All Waivers", description: "View all waivers in the system" },
      { id: "waiver:read", label: "Read Own Waivers", description: "View waivers for your projects" },
      { id: "waiver:manage", label: "Manage Waivers", description: "Create global waivers" },
      { id: "waiver:delete", label: "Delete Waivers", description: "Delete any waiver" },
    ]
  },
  {
    title: "Integrations",
    permissions: [
      { id: "webhook:create", label: "Create Webhooks", description: "Create webhooks for any project" },
      { id: "webhook:delete", label: "Delete Webhooks", description: "Delete any webhook" },
    ]
  }
];

export default function UsersPage() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isInviteDialogOpen, setIsInviteDialogOpen] = useState(false);
  const [isPermissionDialogOpen, setIsPermissionDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  
  // Create form state
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Invite form state
  const [inviteEmail, setInviteEmail] = useState("");
  const [page, setPage] = useState(0);
  const limit = 20;
  
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const { data: users, isLoading, error } = useQuery({
    queryKey: ['users', page],
    queryFn: () => getUsers(page * limit, limit),
  });

  const inviteUserMutation = useMutation({
    mutationFn: (email: string) => inviteUser(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsInviteDialogOpen(false);
      setInviteEmail("");
      toast.success("Invitation sent", {
        description: "An invitation email has been sent to the user.",
      });
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: error.response?.data?.detail || "Failed to send invitation",
      });
    }
  });

  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) => deleteUser(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsDeleteDialogOpen(false);
      setUserToDelete(null);
      toast.success("User deleted successfully");
    },
    onError: (error: any) => {
      toast.error("Failed to delete user", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  });

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: getProjects,
  });

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: getTeams,
  });

  const createUserMutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setIsCreateDialogOpen(false);
      setUsername("");
      setEmail("");
      setPassword("");
      toast.success("User created", {
        description: "The user has been successfully created.",
      });
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: error.response?.data?.detail || "Failed to create user.",
      });
    },
  });

  const updateUserMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => updateUser(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      toast.success("Success", {
        description: "User updated successfully.",
      });
    },
    onError: (error: any) => {
      toast.error("Error", {
        description: error.response?.data?.detail || "Failed to update user.",
      });
    },
  });

  const handleCreateUser = (e: React.FormEvent) => {
    e.preventDefault();
    createUserMutation.mutate({
      username,
      email,
      password,
      permissions: [],
    });
  };

  const handlePermissionChange = (permission: string, hasPermission: boolean) => {
    if (!selectedUser) return;
    
    let newPermissions = [...selectedUser.permissions];
    if (hasPermission) {
      if (!newPermissions.includes(permission)) {
        newPermissions.push(permission);
      }
    } else {
      newPermissions = newPermissions.filter(p => p !== permission);
    }
    
    // Optimistic update for UI
    setSelectedUser({ ...selectedUser, permissions: newPermissions });
    
    updateUserMutation.mutate({
      id: selectedUser.id,
      data: { permissions: newPermissions }
    });
  };

  const handleToggleStatus = () => {
    if (!selectedUser) return;
    
    const newStatus = !selectedUser.is_active;
    
    // Optimistic update for UI
    setSelectedUser({ ...selectedUser, is_active: newStatus });
    
    updateUserMutation.mutate({
      id: selectedUser.id,
      data: { is_active: newStatus }
    });
  };

  const getUserProjects = (userId: string) => {
    if (!projects) return [];
    return projects.filter(p => p.owner_id === userId || p.members?.some(m => m.user_id === userId));
  };
  
  const getUserTeams = (userId: string) => {
    if (!teams) return [];
    return teams.filter(t => t.members.some(m => m.user_id === userId));
  };

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Spinner size={48} />
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
            <Dialog open={isInviteDialogOpen} onOpenChange={setIsInviteDialogOpen}>
              <DialogTrigger asChild>
                <Button variant="outline">
                  <Mail className="mr-2 h-4 w-4" />
                  Invite User
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Invite User</DialogTitle>
                  <DialogDescription>
                    Send an invitation email to a new user. They will be able to set their own password.
                  </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleInviteUser} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="invite-email">Email</Label>
                    <Input
                      id="invite-email"
                      type="email"
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      required
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={inviteUserMutation.isPending}>
                    {inviteUserMutation.isPending ? "Sending..." : "Send Invitation"}
                  </Button>
                </form>
              </DialogContent>
            </Dialog>
          )}

          {hasPermission('user:create') && (
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="mr-2 h-4 w-4" />
                  Create User
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create New User</DialogTitle>
                  <DialogDescription>
                    Manually create a new user account.
                  </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleCreateUser} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="username">Username</Label>
                    <Input
                      id="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <Input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="password">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={createUserMutation.isPending}>
                    {createUserMutation.isPending ? "Creating..." : "Create User"}
                  </Button>
                </form>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Users</CardTitle>
        </CardHeader>
        <CardContent>
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
                    key={user.id} 
                    className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted cursor-pointer"
                    onClick={() => setSelectedUser(user)}
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
                      {user.is_active ? (
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
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-end space-x-2 py-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={!users || users.length < limit}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog open={!!selectedUser} onOpenChange={(open) => !open && setSelectedUser(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>User Details: {selectedUser?.username}</DialogTitle>
          </DialogHeader>
          
          {selectedUser && (
            <div className="grid gap-6 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Email</Label>
                  <div className="text-sm font-medium">{selectedUser.email}</div>
                </div>
                <div>
                  <Label>Status</Label>
                  <div className="flex items-center gap-2">
                    {selectedUser.is_active ? (
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
                          {selectedUser.is_active ? "Deactivate" : "Activate"}
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
                    {selectedUser.permissions.length === 0 && <span className="text-sm text-muted-foreground">No permissions assigned.</span>}
                    {selectedUser.permissions.includes('*') && (
                        <span className="inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-primary text-primary-foreground hover:bg-primary/80">
                            Administrator
                        </span>
                    )}
                    {selectedUser.permissions.filter(p => p !== '*').slice(0, 5).map(p => (
                        <span key={p} className="inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                            {p}
                        </span>
                    ))}
                    {selectedUser.permissions.filter(p => p !== '*').length > 5 && (
                        <span className="text-xs text-muted-foreground flex items-center">
                            +{selectedUser.permissions.filter(p => p !== '*').length - 5} more
                        </span>
                    )}
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-lg font-medium flex items-center gap-2">
                  <Folder className="h-5 w-5" /> Projects
                </h3>
                <div className="border rounded-md p-4">
                  {getUserProjects(selectedUser.id).length > 0 ? (
                    <ul className="space-y-2">
                      {getUserProjects(selectedUser.id).map(project => (
                        <li key={project._id} className="flex items-center justify-between">
                          <span>{project.name}</span>
                          <Button variant="outline" size="sm" asChild>
                            <Link to={`/projects/${project._id}`}>View</Link>
                          </Button>
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
                  {getUserTeams(selectedUser.id).length > 0 ? (
                    <ul className="space-y-2">
                      {getUserTeams(selectedUser.id).map(team => (
                        <li key={team._id} className="flex items-center justify-between">
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

      <Dialog open={isPermissionDialogOpen} onOpenChange={setIsPermissionDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Manage Permissions for {selectedUser?.username}</DialogTitle>
            <DialogDescription>
                Select the permissions you want to assign to this user.
            </DialogDescription>
          </DialogHeader>
          
          {selectedUser && (
            <div className="grid gap-6 py-4">
                {PERMISSION_GROUPS.map((group) => (
                    <div key={group.title} className="space-y-3">
                        <h4 className="font-medium text-sm text-muted-foreground border-b pb-1">{group.title}</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                            {group.permissions.map((perm) => (
                                <div key={perm.id} className="flex items-start space-x-2">
                                    <Checkbox 
                                        id={`perm-dialog-${perm.id}`} 
                                        checked={selectedUser.permissions.includes(perm.id)}
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
            <Button onClick={() => setIsPermissionDialogOpen(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
                onClick={() => userToDelete && deleteUserMutation.mutate(userToDelete.id)}
                disabled={deleteUserMutation.isPending}
            >
              {deleteUserMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
