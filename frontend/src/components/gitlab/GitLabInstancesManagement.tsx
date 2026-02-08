import { useState } from "react";
import { Plus, Trash2, Edit2, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { gitlabInstancesApi } from "@/api/gitlab-instances";
import { GitLabInstance, GitLabInstanceCreate, GitLabInstanceUpdate } from "@/types/gitlab";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";

interface GitLabInstanceFormData {
  name: string;
  url: string;
  description: string;
  access_token: string;
  oidc_audience: string;
  auto_create_projects: boolean;
  sync_teams: boolean;
  is_active: boolean;
  is_default: boolean;
}

const emptyFormData: GitLabInstanceFormData = {
  name: "",
  url: "",
  description: "",
  access_token: "",
  oidc_audience: "",
  auto_create_projects: false,
  sync_teams: false,
  is_active: true,
  is_default: false,
};

export function GitLabInstancesManagement() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [deleteInstanceId, setDeleteInstanceId] = useState<string | null>(null);
  const [editingInstance, setEditingInstance] = useState<GitLabInstance | null>(null);
  const [formData, setFormData] = useState<GitLabInstanceFormData>(emptyFormData);
  const [testingInstanceId, setTestingInstanceId] = useState<string | null>(null);

  const queryClient = useQueryClient();

  // Fetch instances
  const { data: instancesData, isLoading } = useQuery({
    queryKey: ["gitlab-instances"],
    queryFn: () => gitlabInstancesApi.list(),
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: GitLabInstanceCreate) => gitlabInstancesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gitlab-instances"] });
      toast.success("GitLab instance created successfully");
      setIsCreateDialogOpen(false);
      setFormData(emptyFormData);
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to create instance");
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: GitLabInstanceUpdate }) =>
      gitlabInstancesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gitlab-instances"] });
      toast.success("GitLab instance updated successfully");
      setIsEditDialogOpen(false);
      setEditingInstance(null);
      setFormData(emptyFormData);
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to update instance");
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => gitlabInstancesApi.delete(id, false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gitlab-instances"] });
      toast.success("GitLab instance deleted successfully");
      setDeleteInstanceId(null);
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to delete instance");
    },
  });

  // Test connection mutation
  const testConnectionMutation = useMutation({
    mutationFn: (id: string) => gitlabInstancesApi.testConnection(id),
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Connection successful!`, {
          description: data.gitlab_version
            ? `GitLab version: ${data.gitlab_version}`
            : undefined,
        });
      } else {
        toast.error("Connection failed", {
          description: data.message,
        });
      }
      setTestingInstanceId(null);
    },
    onError: () => {
      toast.error("Connection test failed");
      setTestingInstanceId(null);
    },
  });

  const handleCreate = () => {
    const createData: GitLabInstanceCreate = {
      name: formData.name,
      url: formData.url,
      description: formData.description || undefined,
      access_token: formData.access_token,
      oidc_audience: formData.oidc_audience || undefined,
      auto_create_projects: formData.auto_create_projects,
      sync_teams: formData.sync_teams,
      is_active: formData.is_active,
      is_default: formData.is_default,
    };
    createMutation.mutate(createData);
  };

  const handleUpdate = () => {
    if (!editingInstance) return;

    const updateData: GitLabInstanceUpdate = {
      name: formData.name,
      url: formData.url,
      description: formData.description || undefined,
      access_token: formData.access_token || undefined,
      oidc_audience: formData.oidc_audience || undefined,
      auto_create_projects: formData.auto_create_projects,
      sync_teams: formData.sync_teams,
      is_active: formData.is_active,
      is_default: formData.is_default,
    };
    updateMutation.mutate({ id: editingInstance.id, data: updateData });
  };

  const handleEdit = (instance: GitLabInstance) => {
    setEditingInstance(instance);
    setFormData({
      name: instance.name,
      url: instance.url,
      description: instance.description || "",
      access_token: "", // Don't populate password field
      oidc_audience: instance.oidc_audience || "",
      auto_create_projects: instance.auto_create_projects,
      sync_teams: instance.sync_teams,
      is_active: instance.is_active,
      is_default: instance.is_default,
    });
    setIsEditDialogOpen(true);
  };

  const handleTestConnection = (instanceId: string) => {
    setTestingInstanceId(instanceId);
    testConnectionMutation.mutate(instanceId);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>GitLab Instances</CardTitle>
            <CardDescription>
              Manage multiple GitLab instances for SBOM ingestion and CI/CD integration.
            </CardDescription>
          </div>
          <Button onClick={() => setIsCreateDialogOpen(true)} size="sm">
            <Plus className="h-4 w-4 mr-2" />
            Add Instance
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : instancesData?.items.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <p>No GitLab instances configured yet.</p>
            <p className="text-sm mt-2">Click "Add Instance" to get started.</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Features</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {instancesData?.items.map((instance) => (
                <TableRow key={instance.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {instance.name}
                      {instance.is_default && (
                        <Badge variant="secondary">Default</Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {instance.url}
                  </TableCell>
                  <TableCell>
                    {instance.is_active ? (
                      <Badge variant="default" className="gap-1">
                        <CheckCircle2 className="h-3 w-3" />
                        Active
                      </Badge>
                    ) : (
                      <Badge variant="secondary" className="gap-1">
                        <XCircle className="h-3 w-3" />
                        Inactive
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {instance.auto_create_projects && (
                        <Badge variant="outline" className="text-xs">
                          Auto-Create
                        </Badge>
                      )}
                      {instance.sync_teams && (
                        <Badge variant="outline" className="text-xs">
                          Sync Teams
                        </Badge>
                      )}
                      {!instance.token_configured && (
                        <Badge variant="destructive" className="text-xs">
                          No Token
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTestConnection(instance.id)}
                        disabled={testingInstanceId === instance.id}
                      >
                        {testingInstanceId === instance.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          "Test"
                        )}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleEdit(instance)}
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setDeleteInstanceId(instance.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      {/* Create Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add GitLab Instance</DialogTitle>
            <DialogDescription>
              Configure a new GitLab instance for SBOM ingestion.
            </DialogDescription>
          </DialogHeader>
          <InstanceForm formData={formData} setFormData={setFormData} />
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setIsCreateDialogOpen(false);
                setFormData(emptyFormData);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={createMutation.isPending || !formData.name || !formData.url || !formData.access_token}
            >
              {createMutation.isPending ? "Creating..." : "Create Instance"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit GitLab Instance</DialogTitle>
            <DialogDescription>
              Update the configuration for {editingInstance?.name}.
            </DialogDescription>
          </DialogHeader>
          <InstanceForm formData={formData} setFormData={setFormData} isEdit />
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setIsEditDialogOpen(false);
                setEditingInstance(null);
                setFormData(emptyFormData);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleUpdate}
              disabled={updateMutation.isPending || !formData.name || !formData.url}
            >
              {updateMutation.isPending ? "Updating..." : "Update Instance"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog
        open={deleteInstanceId !== null}
        onOpenChange={() => setDeleteInstanceId(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete GitLab Instance?</DialogTitle>
            <DialogDescription>
              This will remove the GitLab instance configuration. Projects linked to
              this instance will lose their GitLab integration.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteInstanceId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteInstanceId && deleteMutation.mutate(deleteInstanceId)}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// Form component
function InstanceForm({
  formData,
  setFormData,
  isEdit = false,
}: {
  formData: GitLabInstanceFormData;
  setFormData: React.Dispatch<React.SetStateAction<GitLabInstanceFormData>>;
  isEdit?: boolean;
}) {
  return (
    <div className="space-y-4">
      <div className="grid gap-2">
        <Label htmlFor="name">Name *</Label>
        <Input
          id="name"
          placeholder="e.g., GitLab.com, Internal GitLab"
          value={formData.name}
          onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
        />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="url">URL *</Label>
        <Input
          id="url"
          placeholder="https://gitlab.example.com"
          value={formData.url}
          onChange={(e) => setFormData((prev) => ({ ...prev, url: e.target.value }))}
        />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          placeholder="Optional description"
          value={formData.description}
          onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
          rows={2}
        />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="access_token">
          Access Token {isEdit && "(leave empty to keep current)"}
        </Label>
        <Input
          id="access_token"
          type="password"
          placeholder="glpat-..."
          value={formData.access_token}
          onChange={(e) => setFormData((prev) => ({ ...prev, access_token: e.target.value }))}
        />
        <p className="text-sm text-muted-foreground">
          Personal or Group Access Token with 'api' scope for MR comments and team sync.
        </p>
      </div>

      <div className="grid gap-2">
        <Label htmlFor="oidc_audience">OIDC Audience</Label>
        <Input
          id="oidc_audience"
          placeholder="https://dependencycontrol.example.com"
          value={formData.oidc_audience}
          onChange={(e) => setFormData((prev) => ({ ...prev, oidc_audience: e.target.value }))}
        />
        <p className="text-sm text-muted-foreground">
          Expected 'aud' claim for OIDC tokens from this instance (optional).
        </p>
      </div>

      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between">
          <Label htmlFor="is_active">Active</Label>
          <Switch
            id="is_active"
            checked={formData.is_active}
            onCheckedChange={(checked) =>
              setFormData((prev) => ({ ...prev, is_active: checked }))
            }
          />
        </div>

        <div className="flex items-center justify-between">
          <Label htmlFor="is_default">Default Instance</Label>
          <Switch
            id="is_default"
            checked={formData.is_default}
            onCheckedChange={(checked) =>
              setFormData((prev) => ({ ...prev, is_default: checked }))
            }
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="auto_create_projects">Auto-Create Projects</Label>
            <p className="text-xs text-muted-foreground">
              Automatically create projects from OIDC tokens
            </p>
          </div>
          <Switch
            id="auto_create_projects"
            checked={formData.auto_create_projects}
            onCheckedChange={(checked) =>
              setFormData((prev) => ({ ...prev, auto_create_projects: checked }))
            }
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="sync_teams">Sync Teams</Label>
            <p className="text-xs text-muted-foreground">
              Sync GitLab group members to local teams
            </p>
          </div>
          <Switch
            id="sync_teams"
            checked={formData.sync_teams}
            onCheckedChange={(checked) =>
              setFormData((prev) => ({ ...prev, sync_teams: checked }))
            }
          />
        </div>
      </div>
    </div>
  );
}
