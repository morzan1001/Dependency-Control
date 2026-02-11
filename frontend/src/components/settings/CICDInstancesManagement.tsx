import { useState, useMemo } from "react";
import { Plus, Trash2, Edit2, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { gitlabInstancesApi } from "@/api/gitlab-instances";
import { githubInstancesApi } from "@/api/github-instances";
import { GitLabInstance, GitLabInstanceCreate, GitLabInstanceUpdate } from "@/types/gitlab";
import { GitHubInstance, GitHubInstanceCreate, GitHubInstanceUpdate } from "@/types/github";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";

type InstanceType = "gitlab" | "github";

type UnifiedInstance = {
  _type: InstanceType;
  id: string;
  name: string;
  url: string;
  description?: string;
  is_active: boolean;
  oidc_audience?: string;
  auto_create_projects: boolean;
  created_at: string;
  // GitLab-specific
  is_default?: boolean;
  sync_teams?: boolean;
  token_configured?: boolean;
  // GitHub-specific
  github_url?: string;
};

interface InstanceFormData {
  type: InstanceType;
  name: string;
  url: string;
  description: string;
  oidc_audience: string;
  is_active: boolean;
  auto_create_projects: boolean;
  // GitLab-specific
  access_token: string;
  sync_teams: boolean;
  is_default: boolean;
  // GitHub-specific
  github_url: string;
}

const emptyFormData: InstanceFormData = {
  type: "gitlab",
  name: "",
  url: "",
  description: "",
  oidc_audience: "",
  is_active: true,
  auto_create_projects: false,
  access_token: "",
  sync_teams: false,
  is_default: false,
  github_url: "",
};

function mergeInstances(
  gitlabItems: GitLabInstance[] | undefined,
  githubItems: GitHubInstance[] | undefined
): UnifiedInstance[] {
  const merged: UnifiedInstance[] = [];

  if (gitlabItems) {
    for (const gl of gitlabItems) {
      merged.push({
        _type: "gitlab",
        id: gl.id,
        name: gl.name,
        url: gl.url,
        description: gl.description,
        is_active: gl.is_active,
        oidc_audience: gl.oidc_audience,
        auto_create_projects: gl.auto_create_projects,
        created_at: gl.created_at,
        is_default: gl.is_default,
        sync_teams: gl.sync_teams,
        token_configured: gl.token_configured,
      });
    }
  }

  if (githubItems) {
    for (const gh of githubItems) {
      merged.push({
        _type: "github",
        id: gh.id,
        name: gh.name,
        url: gh.url,
        description: gh.description,
        is_active: gh.is_active,
        oidc_audience: gh.oidc_audience,
        auto_create_projects: gh.auto_create_projects,
        created_at: gh.created_at,
        github_url: gh.github_url,
      });
    }
  }

  return merged.sort((a, b) => a.name.localeCompare(b.name));
}

export function CICDInstancesManagement() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [deleteInstance, setDeleteInstance] = useState<UnifiedInstance | null>(null);
  const [editingInstance, setEditingInstance] = useState<UnifiedInstance | null>(null);
  const [formData, setFormData] = useState<InstanceFormData>(emptyFormData);
  const [testingInstanceId, setTestingInstanceId] = useState<string | null>(null);

  const queryClient = useQueryClient();

  // Fetch both instance types
  const { data: gitlabData, isLoading: gitlabLoading } = useQuery({
    queryKey: ["gitlab-instances"],
    queryFn: () => gitlabInstancesApi.list(),
  });

  const { data: githubData, isLoading: githubLoading } = useQuery({
    queryKey: ["github-instances"],
    queryFn: () => githubInstancesApi.list(),
  });

  const isLoading = gitlabLoading || githubLoading;

  const instances = useMemo(
    () => mergeInstances(gitlabData?.items, githubData?.items),
    [gitlabData, githubData]
  );

  // GitLab mutations
  const createGitLabMutation = useMutation({
    mutationFn: (data: GitLabInstanceCreate) => gitlabInstancesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gitlab-instances"] });
      toast.success("GitLab instance created successfully");
      closeCreateDialog();
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to create instance");
    },
  });

  const updateGitLabMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: GitLabInstanceUpdate }) =>
      gitlabInstancesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gitlab-instances"] });
      toast.success("GitLab instance updated successfully");
      closeEditDialog();
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to update instance");
    },
  });

  const deleteGitLabMutation = useMutation({
    mutationFn: (id: string) => gitlabInstancesApi.delete(id, false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gitlab-instances"] });
      toast.success("GitLab instance deleted successfully");
      setDeleteInstance(null);
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to delete instance");
    },
  });

  const testGitLabMutation = useMutation({
    mutationFn: (id: string) => gitlabInstancesApi.testConnection(id),
    onSuccess: (data) => {
      if (data.success) {
        toast.success("Connection successful!", {
          description: data.gitlab_version
            ? `GitLab version: ${data.gitlab_version}`
            : undefined,
        });
      } else {
        toast.error("Connection failed", { description: data.message });
      }
      setTestingInstanceId(null);
    },
    onError: () => {
      toast.error("Connection test failed");
      setTestingInstanceId(null);
    },
  });

  // GitHub mutations
  const createGitHubMutation = useMutation({
    mutationFn: (data: GitHubInstanceCreate) => githubInstancesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["github-instances"] });
      toast.success("GitHub instance created successfully");
      closeCreateDialog();
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to create instance");
    },
  });

  const updateGitHubMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: GitHubInstanceUpdate }) =>
      githubInstancesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["github-instances"] });
      toast.success("GitHub instance updated successfully");
      closeEditDialog();
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to update instance");
    },
  });

  const deleteGitHubMutation = useMutation({
    mutationFn: (id: string) => githubInstancesApi.delete(id, false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["github-instances"] });
      toast.success("GitHub instance deleted successfully");
      setDeleteInstance(null);
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || "Failed to delete instance");
    },
  });

  const testGitHubMutation = useMutation({
    mutationFn: (id: string) => githubInstancesApi.testConnection(id),
    onSuccess: (data) => {
      if (data.success) {
        toast.success("Connection successful!", { description: data.message });
      } else {
        toast.error("Connection failed", { description: data.message });
      }
      setTestingInstanceId(null);
    },
    onError: () => {
      toast.error("Connection test failed");
      setTestingInstanceId(null);
    },
  });

  const isCreatePending = createGitLabMutation.isPending || createGitHubMutation.isPending;
  const isUpdatePending = updateGitLabMutation.isPending || updateGitHubMutation.isPending;
  const isDeletePending = deleteGitLabMutation.isPending || deleteGitHubMutation.isPending;

  const closeCreateDialog = () => {
    setIsCreateDialogOpen(false);
    setFormData(emptyFormData);
  };

  const closeEditDialog = () => {
    setIsEditDialogOpen(false);
    setEditingInstance(null);
    setFormData(emptyFormData);
  };

  const handleCreate = () => {
    if (formData.type === "gitlab") {
      const data: GitLabInstanceCreate = {
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
      createGitLabMutation.mutate(data);
    } else {
      const data: GitHubInstanceCreate = {
        name: formData.name,
        url: formData.url,
        github_url: formData.github_url || undefined,
        description: formData.description || undefined,
        oidc_audience: formData.oidc_audience || undefined,
        auto_create_projects: formData.auto_create_projects,
        is_active: formData.is_active,
      };
      createGitHubMutation.mutate(data);
    }
  };

  const handleUpdate = () => {
    if (!editingInstance) return;

    if (editingInstance._type === "gitlab") {
      const data: GitLabInstanceUpdate = {
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
      updateGitLabMutation.mutate({ id: editingInstance.id, data });
    } else {
      const data: GitHubInstanceUpdate = {
        name: formData.name,
        url: formData.url,
        github_url: formData.github_url || undefined,
        description: formData.description || undefined,
        oidc_audience: formData.oidc_audience || undefined,
        auto_create_projects: formData.auto_create_projects,
        is_active: formData.is_active,
      };
      updateGitHubMutation.mutate({ id: editingInstance.id, data });
    }
  };

  const handleEdit = (instance: UnifiedInstance) => {
    setEditingInstance(instance);
    setFormData({
      type: instance._type,
      name: instance.name,
      url: instance.url,
      description: instance.description || "",
      oidc_audience: instance.oidc_audience || "",
      is_active: instance.is_active,
      auto_create_projects: instance.auto_create_projects,
      access_token: "",
      sync_teams: instance.sync_teams || false,
      is_default: instance.is_default || false,
      github_url: instance.github_url || "",
    });
    setIsEditDialogOpen(true);
  };

  const handleDelete = (instance: UnifiedInstance) => {
    if (instance._type === "gitlab") {
      deleteGitLabMutation.mutate(instance.id);
    } else {
      deleteGitHubMutation.mutate(instance.id);
    }
  };

  const handleTestConnection = (instance: UnifiedInstance) => {
    setTestingInstanceId(instance.id);
    if (instance._type === "gitlab") {
      testGitLabMutation.mutate(instance.id);
    } else {
      testGitHubMutation.mutate(instance.id);
    }
  };

  const isCreateDisabled = () => {
    if (isCreatePending || !formData.name || !formData.url) return true;
    if (formData.type === "gitlab" && !formData.access_token) return true;
    return false;
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>CI/CD Instances</CardTitle>
            <CardDescription>
              Manage GitLab and GitHub instances for OIDC-based SBOM ingestion and CI/CD integration.
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
        ) : instances.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <p>No CI/CD instances configured yet.</p>
            <p className="text-sm mt-2">Click "Add Instance" to connect GitLab or GitHub.</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Features</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {instances.map((instance) => (
                <TableRow key={`${instance._type}-${instance.id}`}>
                  <TableCell>
                    <Badge
                      variant={instance._type === "gitlab" ? "default" : "secondary"}
                      className="text-xs"
                    >
                      {instance._type === "gitlab" ? "GitLab" : "GitHub"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {instance.name}
                      {instance.is_default && (
                        <Badge variant="outline" className="text-xs">
                          Default
                        </Badge>
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
                    <div className="flex gap-1 flex-wrap">
                      {instance.auto_create_projects && (
                        <Badge variant="outline" className="text-xs">
                          Auto-Create
                        </Badge>
                      )}
                      {instance._type === "gitlab" && instance.sync_teams && (
                        <Badge variant="outline" className="text-xs">
                          Sync Teams
                        </Badge>
                      )}
                      {instance._type === "gitlab" && !instance.token_configured && (
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
                        onClick={() => handleTestConnection(instance)}
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
                        onClick={() => setDeleteInstance(instance)}
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
      <Dialog open={isCreateDialogOpen} onOpenChange={(open) => { if (!open) closeCreateDialog(); }}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add CI/CD Instance</DialogTitle>
            <DialogDescription>
              Configure a new GitLab or GitHub instance for SBOM ingestion.
            </DialogDescription>
          </DialogHeader>
          <InstanceForm formData={formData} setFormData={setFormData} showTypeSelector />
          <DialogFooter>
            <Button variant="outline" onClick={closeCreateDialog}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={isCreateDisabled()}>
              {isCreatePending ? "Creating..." : "Create Instance"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={(open) => { if (!open) closeEditDialog(); }}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              Edit {editingInstance?._type === "gitlab" ? "GitLab" : "GitHub"} Instance
            </DialogTitle>
            <DialogDescription>
              Update the configuration for {editingInstance?.name}.
            </DialogDescription>
          </DialogHeader>
          <InstanceForm formData={formData} setFormData={setFormData} isEdit />
          <DialogFooter>
            <Button variant="outline" onClick={closeEditDialog}>
              Cancel
            </Button>
            <Button
              onClick={handleUpdate}
              disabled={isUpdatePending || !formData.name || !formData.url}
            >
              {isUpdatePending ? "Updating..." : "Update Instance"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog
        open={deleteInstance !== null}
        onOpenChange={() => setDeleteInstance(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {deleteInstance?._type === "gitlab" ? "GitLab" : "GitHub"} Instance?</DialogTitle>
            <DialogDescription>
              This will remove the {deleteInstance?._type === "gitlab" ? "GitLab" : "GitHub"} instance
              "{deleteInstance?.name}". Projects linked to this instance will lose their CI/CD integration.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteInstance(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteInstance && handleDelete(deleteInstance)}
              disabled={isDeletePending}
            >
              {isDeletePending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// Form component with conditional fields based on instance type
function InstanceForm({
  formData,
  setFormData,
  isEdit = false,
  showTypeSelector = false,
}: {
  formData: InstanceFormData;
  setFormData: React.Dispatch<React.SetStateAction<InstanceFormData>>;
  isEdit?: boolean;
  showTypeSelector?: boolean;
}) {
  return (
    <div className="space-y-4">
      {/* Type selector (only on create) */}
      {showTypeSelector && (
        <div className="grid gap-2">
          <Label>Provider Type *</Label>
          <Select
            value={formData.type}
            onValueChange={(value: InstanceType) =>
              setFormData((prev) => ({ ...emptyFormData, type: value, is_active: prev.is_active }))
            }
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="gitlab">GitLab</SelectItem>
              <SelectItem value="github">GitHub</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Type badge (on edit) */}
      {isEdit && (
        <div className="flex items-center gap-2">
          <Label>Provider Type</Label>
          <Badge variant={formData.type === "gitlab" ? "default" : "secondary"}>
            {formData.type === "gitlab" ? "GitLab" : "GitHub"}
          </Badge>
        </div>
      )}

      {/* Common fields */}
      <div className="grid gap-2">
        <Label htmlFor="ci-name">Name *</Label>
        <Input
          id="ci-name"
          placeholder={formData.type === "gitlab" ? "e.g., GitLab.com, Internal GitLab" : "e.g., GitHub.com, GitHub Enterprise"}
          value={formData.name}
          onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
        />
      </div>

      <div className="grid gap-2">
        <Label htmlFor="ci-url">
          {formData.type === "gitlab" ? "URL *" : "OIDC Issuer URL *"}
        </Label>
        <Input
          id="ci-url"
          placeholder={formData.type === "gitlab" ? "https://gitlab.example.com" : "https://token.actions.githubusercontent.com"}
          value={formData.url}
          onChange={(e) => setFormData((prev) => ({ ...prev, url: e.target.value }))}
        />
        {formData.type === "github" && (
          <p className="text-sm text-muted-foreground">
            For GitHub.com this is{" "}
            <code className="text-xs">https://token.actions.githubusercontent.com</code>
          </p>
        )}
      </div>

      {/* GitHub-specific: Web URL */}
      {formData.type === "github" && (
        <div className="grid gap-2">
          <Label htmlFor="ci-github-url">GitHub Web URL</Label>
          <Input
            id="ci-github-url"
            placeholder="https://github.com"
            value={formData.github_url}
            onChange={(e) => setFormData((prev) => ({ ...prev, github_url: e.target.value }))}
          />
          <p className="text-sm text-muted-foreground">
            Optional. The GitHub web interface URL (for links in the UI).
          </p>
        </div>
      )}

      <div className="grid gap-2">
        <Label htmlFor="ci-description">Description</Label>
        <Textarea
          id="ci-description"
          placeholder="Optional description"
          value={formData.description}
          onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
          rows={2}
        />
      </div>

      {/* GitLab-specific: Access Token */}
      {formData.type === "gitlab" && (
        <div className="grid gap-2">
          <Label htmlFor="ci-access-token">
            Access Token {isEdit ? "(leave empty to keep current)" : "*"}
          </Label>
          <Input
            id="ci-access-token"
            type="password"
            placeholder="glpat-..."
            value={formData.access_token}
            onChange={(e) => setFormData((prev) => ({ ...prev, access_token: e.target.value }))}
          />
          <p className="text-sm text-muted-foreground">
            Personal or Group Access Token with 'api' scope for MR comments and team sync.
          </p>
        </div>
      )}

      <div className="grid gap-2">
        <Label htmlFor="ci-oidc-audience">OIDC Audience</Label>
        <Input
          id="ci-oidc-audience"
          placeholder={formData.type === "gitlab" ? "https://dependencycontrol.example.com" : "dependency-control"}
          value={formData.oidc_audience}
          onChange={(e) => setFormData((prev) => ({ ...prev, oidc_audience: e.target.value }))}
        />
        <p className="text-sm text-muted-foreground">
          Expected 'aud' claim for OIDC tokens from this instance (optional).
        </p>
      </div>

      {/* Toggle switches */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between">
          <Label htmlFor="ci-is-active">Active</Label>
          <Switch
            id="ci-is-active"
            checked={formData.is_active}
            onCheckedChange={(checked) =>
              setFormData((prev) => ({ ...prev, is_active: checked }))
            }
          />
        </div>

        {/* GitLab-specific: Default Instance */}
        {formData.type === "gitlab" && (
          <div className="flex items-center justify-between">
            <Label htmlFor="ci-is-default">Default Instance</Label>
            <Switch
              id="ci-is-default"
              checked={formData.is_default}
              onCheckedChange={(checked) =>
                setFormData((prev) => ({ ...prev, is_default: checked }))
              }
            />
          </div>
        )}

        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="ci-auto-create">Auto-Create Projects</Label>
            <p className="text-xs text-muted-foreground">
              Automatically create projects from OIDC tokens
            </p>
          </div>
          <Switch
            id="ci-auto-create"
            checked={formData.auto_create_projects}
            onCheckedChange={(checked) =>
              setFormData((prev) => ({ ...prev, auto_create_projects: checked }))
            }
          />
        </div>

        {/* GitLab-specific: Sync Teams */}
        {formData.type === "gitlab" && (
          <div className="flex items-center justify-between">
            <div>
              <Label htmlFor="ci-sync-teams">Sync Teams</Label>
              <p className="text-xs text-muted-foreground">
                Sync GitLab group members to local teams
              </p>
            </div>
            <Switch
              id="ci-sync-teams"
              checked={formData.sync_teams}
              onCheckedChange={(checked) =>
                setFormData((prev) => ({ ...prev, sync_teams: checked }))
              }
            />
          </div>
        )}
      </div>
    </div>
  );
}
