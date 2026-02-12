import { useState } from 'react'
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { gitlabInstancesApi } from '@/api/gitlab-instances'
import { useAppConfig } from '@/hooks/queries/use-system'
import { useTeams } from '@/hooks/queries/use-teams'
import { useProjectBranches, useUpdateProjectNotifications, useTransferOwnership } from '@/hooks/queries/use-projects'
import { useProjectWebhooks, useCreateProjectWebhook, useDeleteWebhook } from '@/hooks/queries/use-webhooks'
import { WebhookCreate } from '@/types/webhook'
import { Project, ProjectUpdate } from '@/types/project'
import { User } from '@/types/user'
import { getErrorMessage } from '@/lib/utils'
import { useAuth } from '@/context/useAuth'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { WebhookManager } from '@/components/WebhookManager'
import { AlertTriangle, RefreshCw, Copy, Trash2, Info, ArrowRightLeft } from 'lucide-react'
import { toast } from "sonner"
import { useNavigate } from 'react-router-dom'
import { AVAILABLE_ANALYZERS, ANALYZER_CATEGORIES } from '@/lib/constants'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

interface ProjectSettingsProps {
  project: Project
  projectId: string
  user: User
}

export function ProjectSettings({ project, projectId, user }: ProjectSettingsProps) {
  const queryClient = useQueryClient()
  const { hasPermission } = useAuth()
  const navigate = useNavigate()
  
  const [name, setName] = useState(project.name)
  const [teamId, setTeamId] = useState<string | undefined>(project.team_id || "none")
  const [retentionDays, setRetentionDays] = useState(project.retention_days || 90)
  const [analyzers, setAnalyzers] = useState<string[]>(project.active_analyzers || [])
  const [defaultBranch, setDefaultBranch] = useState<string | undefined>(project.default_branch)
  const [rescanEnabled, setRescanEnabled] = useState<boolean | undefined>(project.rescan_enabled)
  const [rescanInterval, setRescanInterval] = useState<number | undefined>(project.rescan_interval)
  const [gitlabMrCommentsEnabled, setGitlabMrCommentsEnabled] = useState<boolean>(project.gitlab_mr_comments_enabled || false)
  const [gitlabInstanceId, setGitlabInstanceId] = useState<string | undefined>(project.gitlab_instance_id)
  const [gitlabProjectId, setGitlabProjectId] = useState<number | undefined>(project.gitlab_project_id)
  const [gitlabProjectPath, setGitlabProjectPath] = useState<string | undefined>(project.gitlab_project_path)

  const [apiKey, setApiKey] = useState<string | null>(null)
  const [isApiKeyDialogOpen, setIsApiKeyDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [isTransferDialogOpen, setIsTransferDialogOpen] = useState(false)
  const [transferTargetId, setTransferTargetId] = useState<string>("")
  const [enforceNotificationSettings, setEnforceNotificationSettings] = useState(project.enforce_notification_settings || false)
  
  const [notificationPrefs, setNotificationPrefs] = useState<Record<string, string[]>>(() => {
    if (!project || !user) return {};

    const userId = user.id;

    // Enforced settings always win
    if (project.enforce_notification_settings) {
        return project.owner_notification_preferences || {};
    }

    // Project-level preferences (owner or member)
    let projectPrefs: Record<string, string[]> | undefined;
    if (project.owner_id === userId) {
      projectPrefs = project.owner_notification_preferences;
    } else if (project.members) {
      const member = project.members.find(m => m.user_id === userId);
      if (member?.notification_preferences && Object.keys(member.notification_preferences).length > 0) {
        projectPrefs = member.notification_preferences;
      }
    }

    // Use project-level preferences if set, otherwise fall back to global user preferences
    if (projectPrefs && Object.keys(projectPrefs).length > 0) {
      return projectPrefs;
    }
    return user.notification_preferences || {};
  })

  // Use centralized hooks for better caching and consistency
  const { data: teams } = useTeams();
  const { data: branches } = useProjectBranches(projectId);
  const { data: appConfig } = useAppConfig();
  const { data: webhooks, isLoading: isLoadingWebhooks, refetch: refetchWebhooks } = useProjectWebhooks(projectId);

  // Fetch GitLab instances
  const { data: gitlabInstances } = useQuery({
    queryKey: ['gitlab-instances'],
    queryFn: () => gitlabInstancesApi.list({ active_only: true }),
  });

  const deleteProjectMutation = useMutation({
    mutationFn: () => projectApi.delete(projectId),
    onSuccess: () => {
      toast.success("Project Deleted", { description: "The project has been permanently deleted." })
      navigate('/projects')
    },
    onError: (error) => {
      toast.error("Delete Failed", { description: getErrorMessage(error) })
    }
  })

  const updateProjectMutation = useMutation({
    mutationFn: (data: ProjectUpdate) => projectApi.update(projectId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      toast.success("Project updated successfully")
    },
    onError: (error) => {
      toast.error("Failed to update project", {
        description: getErrorMessage(error)
      })
    }
  })

  const updateNotificationSettingsMutation = useUpdateProjectNotifications()

  const rotateKeyMutation = useMutation({
    mutationFn: () => projectApi.rotateApiKey(projectId),
    onSuccess: (data) => {
      setApiKey(data.api_key)
      setIsApiKeyDialogOpen(true)
      toast.success("API Key rotated successfully")
    },
    onError: (error) => {
      toast.error("Failed to rotate API key", {
        description: getErrorMessage(error)
      })
    }
  })

  const transferOwnershipMutation = useTransferOwnership()

  const createProjectWebhookMutation = useCreateProjectWebhook()
  const deleteWebhookMutation = useDeleteWebhook()

  // Wrapper to include projectId in the mutation
  const createWebhookMutation = {
    mutateAsync: (data: WebhookCreate) => 
      createProjectWebhookMutation.mutateAsync({ projectId, data }).then(result => {
        refetchWebhooks()
        return result
      }),
    isPending: createProjectWebhookMutation.isPending,
  }

  // Add refetch on delete success
  const handleDeleteWebhook = async (id: string) => {
    await deleteWebhookMutation.mutateAsync(id)
    refetchWebhooks()
  }

  const handleUpdate = (e: React.FormEvent) => {
    e.preventDefault()
    updateProjectMutation.mutate({
      name,
      team_id: teamId === "none" ? null : teamId,
      retention_days: retentionDays,
      active_analyzers: analyzers,
      default_branch: defaultBranch === "none" ? null : defaultBranch,
      rescan_enabled: rescanEnabled,
      rescan_interval: rescanInterval,
      gitlab_mr_comments_enabled: gitlabMrCommentsEnabled,
      gitlab_instance_id: gitlabInstanceId || null,
      gitlab_project_id: gitlabProjectId || null,
      gitlab_project_path: gitlabProjectPath || null,
    })
  }

  const toggleAnalyzer = (analyzerId: string) => {
    setAnalyzers(prev => 
      prev.includes(analyzerId)
        ? prev.filter(a => a !== analyzerId)
        : [...prev, analyzerId]
    )
  }

  const toggleNotification = (event: string, channel: string) => {
    setNotificationPrefs(prev => {
        const currentChannels = prev[event] || []
        const newChannels = currentChannels.includes(channel)
            ? currentChannels.filter(c => c !== channel)
            : [...currentChannels, channel]
        
        return {
            ...prev,
            [event]: newChannels
        }
    })
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
            <CardTitle>General Settings</CardTitle>
            <CardDescription>Manage your project configuration.</CardDescription>
        </CardHeader>
        <CardContent>
            <form onSubmit={handleUpdate} className="space-y-4">
                <div className="grid gap-2">
                    <Label htmlFor="name">Project Name</Label>
                    <Input 
                        id="name" 
                        value={name} 
                        onChange={(e) => setName(e.target.value)} 
                    />
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="team">Team</Label>
                    <Select value={teamId} onValueChange={setTeamId}>
                        <SelectTrigger>
                            <SelectValue placeholder="Select a team" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="none">No Team</SelectItem>
                            {teams?.map((team) => (
                                <SelectItem key={team.id} value={team.id}>
                                    {team.name}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="defaultBranch">Default Branch</Label>
                    <Select value={defaultBranch || "none"} onValueChange={(val) => setDefaultBranch(val === "none" ? undefined : val)}>
                        <SelectTrigger>
                            <SelectValue placeholder="Select default branch" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="none">None (Show All)</SelectItem>
                            {branches?.map((branch) => (
                                <SelectItem key={branch} value={branch}>{branch}</SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                        This branch will be selected by default on the dashboard.
                    </p>
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="retention">Retention Period (Days)</Label>
                    {appConfig?.retention_mode === 'global' ? (
                        <div className="p-3 bg-muted rounded-md text-sm border">
                            <p className="font-medium">Managed Globally</p>
                            <p className="text-muted-foreground mt-1">
                                {appConfig.global_retention_days && appConfig.global_retention_days > 0 
                                    ? `Data is retained for ${appConfig.global_retention_days} days.` 
                                    : "Data retention is disabled (data is kept forever)."}
                            </p>
                        </div>
                    ) : (
                        <Input 
                            id="retention" 
                            type="number" 
                            min="1"
                            value={retentionDays} 
                            onChange={(e) => setRetentionDays(parseInt(e.target.value) || 90)} 
                        />
                    )}
                </div>
                <div className="grid gap-2">
                    <Label>Periodic Re-scanning</Label>
                    {appConfig?.rescan_mode === 'global' ? (
                        <div className="p-3 bg-muted rounded-md text-sm border">
                            <p className="font-medium">Managed Globally</p>
                            <p className="text-muted-foreground mt-1">
                                {appConfig.global_rescan_enabled 
                                    ? `Re-scanning is enabled (every ${appConfig.global_rescan_interval} hours).` 
                                    : "Re-scanning is disabled globally."}
                            </p>
                        </div>
                    ) : (
                        <div className="border rounded-md p-4 space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label className="text-base">Enable Re-scanning</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Automatically re-scan the latest SBOMs periodically.
                                    </p>
                                </div>
                                <Switch
                                    checked={rescanEnabled === true}
                                    onCheckedChange={(checked) => setRescanEnabled(checked)}
                                />
                            </div>
                            
                            {rescanEnabled === true && (
                                <div className="grid gap-2">
                                    <Label htmlFor="rescanInterval">Interval (Hours)</Label>
                                    <Input 
                                        id="rescanInterval" 
                                        type="number" 
                                        min="1"
                                        value={rescanInterval || 24} 
                                        onChange={(e) => setRescanInterval(parseInt(e.target.value) || 24)} 
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        How often to re-scan the project.
                                    </p>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {(gitlabInstances?.items?.length ?? 0) > 0 && (
                    <div className="grid gap-2">
                        <Label>GitLab Integration</Label>
                        <div className="border rounded-md p-4 space-y-4">
                            <div className="grid gap-2">
                                <Label htmlFor="gitlab-instance">GitLab Instance</Label>
                                <Select
                                    value={gitlabInstanceId || "none"}
                                    onValueChange={(value) => setGitlabInstanceId(value === "none" ? undefined : value)}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select GitLab instance" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="none">None (Auto-detect from OIDC)</SelectItem>
                                        {gitlabInstances?.items.map((instance) => (
                                            <SelectItem key={instance.id} value={instance.id}>
                                                {instance.name} ({instance.url})
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                                <p className="text-xs text-muted-foreground">
                                    For manually linked projects. Auto-created projects detect this automatically.
                                </p>
                            </div>

                            {gitlabInstanceId && (
                                <>
                                    <div className="grid gap-2">
                                        <Label htmlFor="gitlab-project-id">GitLab Project ID</Label>
                                        <Input
                                            id="gitlab-project-id"
                                            type="number"
                                            placeholder="12345"
                                            value={gitlabProjectId || ''}
                                            onChange={(e) => setGitlabProjectId(parseInt(e.target.value) || undefined)}
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            The numeric project ID from GitLab (found in project settings).
                                        </p>
                                    </div>

                                    <div className="grid gap-2">
                                        <Label htmlFor="gitlab-project-path">GitLab Project Path (Optional)</Label>
                                        <Input
                                            id="gitlab-project-path"
                                            placeholder="namespace/project-name"
                                            value={gitlabProjectPath || ''}
                                            onChange={(e) => setGitlabProjectPath(e.target.value || undefined)}
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            For display purposes only. Example: "mygroup/myproject"
                                        </p>
                                    </div>

                                    <div className="flex items-center justify-between">
                                        <div className="space-y-0.5">
                                            <Label className="text-base">Merge Request Decoration</Label>
                                            <p className="text-sm text-muted-foreground">
                                                Post scan results as comments on GitLab Merge Requests.
                                            </p>
                                        </div>
                                        <Switch
                                            checked={gitlabMrCommentsEnabled}
                                            onCheckedChange={setGitlabMrCommentsEnabled}
                                        />
                                    </div>
                                </>
                            )}
                        </div>
                    </div>
                )}

                <div className="grid gap-2">
                    <Label>Active Analyzers</Label>
                    <div className="flex flex-col gap-2 border rounded-md p-4 max-h-[300px] overflow-y-auto">
                        {Object.entries(ANALYZER_CATEGORIES).map(([categoryId, categoryInfo]) => {
                          const categoryAnalyzers = AVAILABLE_ANALYZERS.filter(a => a.category === categoryId);
                          if (categoryAnalyzers.length === 0) return null;
                          
                          return (
                            <div key={categoryId} className="mb-3 last:mb-0">
                              <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 pb-1 border-b">
                                {categoryInfo.label}
                              </div>
                              {categoryAnalyzers.map((analyzer) => {
                                const hasRequiredDeps = !analyzer.dependsOn || analyzer.dependsOn.some(dep => analyzers.includes(dep));
                                return (
                                  <div key={analyzer.id} className="flex items-start space-x-2 py-2">
                                    <Checkbox 
                                      id={`settings-analyzer-${analyzer.id}`}
                                      checked={analyzers.includes(analyzer.id)}
                                      onCheckedChange={() => toggleAnalyzer(analyzer.id)}
                                      className="mt-1"
                                    />
                                    <div className="flex flex-col gap-1">
                                      <div className="flex items-center gap-2">
                                        <Label htmlFor={`settings-analyzer-${analyzer.id}`} className="font-medium cursor-pointer">
                                          {analyzer.label}
                                        </Label>
                                        {analyzer.isPostProcessor && (
                                          <span className="text-[10px] px-1.5 py-0.5 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 rounded">
                                            Post-Processor
                                          </span>
                                        )}
                                        {analyzer.requiresCallgraph && (
                                          <span className="text-[10px] px-1.5 py-0.5 bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 rounded">
                                            Callgraph Required
                                          </span>
                                        )}
                                      </div>
                                      <p className="text-xs text-muted-foreground">
                                        {analyzer.description}
                                      </p>
                                      {analyzer.isPostProcessor && !hasRequiredDeps && analyzers.includes(analyzer.id) && (
                                        <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
                                          <AlertTriangle className="h-3 w-3" />
                                          Requires at least one vulnerability scanner to be enabled
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          );
                        })}
                    </div>
                </div>
                {hasPermission('project:update') && (
                    <Button type="submit" disabled={updateProjectMutation.isPending}>
                        {updateProjectMutation.isPending ? "Saving..." : "Save Changes"}
                    </Button>
                )}
            </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
            <CardTitle>Notification Settings</CardTitle>
            <CardDescription>Configure how you want to be notified about project events.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
            {hasPermission('project:update') && (
                <div className="flex flex-row items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                        <Label className="text-base">Enforce Notification Settings</Label>
                        <div className="text-sm text-muted-foreground">
                            If enabled, these settings will be applied to all project members. Members will not be able to change them.
                        </div>
                    </div>
                    <Switch
                        checked={enforceNotificationSettings}
                        onCheckedChange={setEnforceNotificationSettings}
                    />
                </div>
            )}

            {enforceNotificationSettings && !hasPermission('project:update') && (
                <div className="flex items-center gap-2 p-4 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900">
                    <Info className="h-4 w-4" />
                    <p>Notification settings are currently enforced by the project administrator. You cannot modify them.</p>
                </div>
            )}

            {!enforceNotificationSettings && (() => {
                const userId = user.id;
                let hasProjectPrefs = false;
                if (project.owner_id === userId) {
                    hasProjectPrefs = !!(project.owner_notification_preferences && Object.keys(project.owner_notification_preferences).length > 0);
                } else {
                    const member = project.members?.find(m => m.user_id === userId);
                    hasProjectPrefs = !!(member?.notification_preferences && Object.keys(member.notification_preferences).length > 0);
                }
                if (!hasProjectPrefs) {
                    return (
                        <div className="flex items-center gap-2 p-4 text-sm text-blue-800 bg-blue-50 border border-blue-200 rounded-lg dark:bg-blue-950/50 dark:text-blue-200 dark:border-blue-900">
                            <Info className="h-4 w-4 shrink-0" />
                            <p>Showing your global notification preferences. Save to set project-specific overrides.</p>
                        </div>
                    );
                }
                return null;
            })()}

            <div className="border rounded-md">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead className="w-[300px]">Event</TableHead>
                            {['email', 'slack', 'mattermost'].map(channel => {
                                if (channel === 'email' && !appConfig?.notifications.email) return null;
                                if (channel === 'slack' && !appConfig?.notifications.slack) return null;
                                if (channel === 'mattermost' && !appConfig?.notifications.mattermost) return null;
                                return (
                                    <TableHead key={channel} className="capitalize text-center">{channel}</TableHead>
                                );
                            })}
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {['analysis_completed', 'vulnerability_found'].map(event => (
                            <TableRow key={event} className={enforceNotificationSettings && !hasPermission('project:update') ? 'opacity-60' : ''}>
                                <TableCell>
                                    <div className="font-medium capitalize">{event.replace('_', ' ')}</div>
                                    <div className="text-xs text-muted-foreground">
                                        Receive notifications when {event.replace('_', ' ')} occurs.
                                    </div>
                                </TableCell>
                                {['email', 'slack', 'mattermost'].map(channel => {
                                    if (channel === 'email' && !appConfig?.notifications.email) return null;
                                    if (channel === 'slack' && !appConfig?.notifications.slack) return null;
                                    if (channel === 'mattermost' && !appConfig?.notifications.mattermost) return null;
                                    
                                    return (
                                        <TableCell key={channel} className="text-center">
                                            <div className="flex justify-center">
                                                <Checkbox 
                                                    id={`${event}-${channel}`}
                                                    checked={(notificationPrefs[event] || []).includes(channel)}
                                                    onCheckedChange={() => toggleNotification(event, channel)}
                                                    disabled={enforceNotificationSettings && !hasPermission('project:update')}
                                                />
                                            </div>
                                        </TableCell>
                                    );
                                })}
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </div>
            {hasPermission('project:update') && (
                <Button 
                    onClick={() => updateNotificationSettingsMutation.mutate({ 
                        id: project.id,
                        settings: {
                            notification_preferences: notificationPrefs,
                            enforce_notification_settings: enforceNotificationSettings
                        }
                    }, {
                        onSuccess: () => toast.success("Notification settings updated"),
                        onError: () => toast.error("Failed to update notification settings")
                    })}
                    disabled={updateNotificationSettingsMutation.isPending}
                >
                    {updateNotificationSettingsMutation.isPending ? "Saving..." : "Save Notification Settings"}
                </Button>
            )}
        </CardContent>
      </Card>

      <WebhookManager 
        webhooks={webhooks || []} 
        isLoading={isLoadingWebhooks}
        onCreate={createWebhookMutation.mutateAsync}
        onDelete={handleDeleteWebhook}
        createPermission="project:update"
        deletePermission="project:update"
      />

      {(hasPermission('project:update') || hasPermission('project:delete')) && (
        <Card className="border-destructive">
            <CardHeader>
                <CardTitle className="text-destructive flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5" />
                    Danger Zone
                </CardTitle>
                <CardDescription>
                    Destructive actions that cannot be undone.
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                {(project.owner_id === String(user.id) || hasPermission('system:manage')) && (
                    <div className="flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
                        <div>
                            <div className="font-medium">Transfer Ownership</div>
                            <div className="text-sm text-muted-foreground">
                                Transfer this project to another member. The new owner will have full control.
                            </div>
                        </div>
                        <Button variant="destructive" onClick={() => setIsTransferDialogOpen(true)} disabled={project.members.length < 2}>
                            <ArrowRightLeft className="mr-2 h-4 w-4" />
                            Transfer
                        </Button>
                    </div>
                )}

                {hasPermission('project:update') && (
                    <div className="flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
                        <div>
                            <div className="font-medium">Rotate API Key</div>
                            <div className="text-sm text-muted-foreground">
                                Invalidate the current API key and generate a new one.
                            </div>
                        </div>
                        <Button variant="destructive" onClick={() => rotateKeyMutation.mutate()} disabled={rotateKeyMutation.isPending}>
                            {rotateKeyMutation.isPending ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                            Rotate Key
                        </Button>
                    </div>
                )}

                {hasPermission('project:delete') && (
                    <div className="flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
                        <div>
                            <div className="font-medium">Delete Project</div>
                            <div className="text-sm text-muted-foreground">
                                Permanently delete this project and all its data. This action cannot be undone.
                            </div>
                        </div>
                        <Button variant="destructive" onClick={() => setIsDeleteDialogOpen(true)}>
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete Project
                        </Button>
                    </div>
                )}
            </CardContent>
        </Card>
      )}

      <Dialog open={isApiKeyDialogOpen} onOpenChange={setIsApiKeyDialogOpen}>
        <DialogContent>
            <DialogHeader>
                <DialogTitle>New API Key Generated</DialogTitle>
                <DialogDescription>
                    Please copy your new API key. It will not be shown again.
                </DialogDescription>
            </DialogHeader>
            <div className="flex items-center space-x-2 mt-4">
                <Input value={apiKey || ''} readOnly />
                <Button size="icon" onClick={() => {
                    navigator.clipboard.writeText(apiKey || '')
                    toast.success("Copied to clipboard")
                }}>
                    <Copy className="h-4 w-4" />
                </Button>
            </div>
            <DialogFooter>
                <Button onClick={() => setIsApiKeyDialogOpen(false)}>Close</Button>
            </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <DialogContent>
            <DialogHeader>
                <DialogTitle>Delete Project</DialogTitle>
                <DialogDescription>
                    Are you sure you want to delete this project? This action cannot be undone and will permanently remove all scans, findings, and settings associated with <strong>{project.name}</strong>.
                </DialogDescription>
            </DialogHeader>
            <DialogFooter>
                <Button variant="outline" onClick={() => setIsDeleteDialogOpen(false)}>Cancel</Button>
                <Button
                    variant="destructive"
                    onClick={() => deleteProjectMutation.mutate()}
                    disabled={deleteProjectMutation.isPending}
                >
                    {deleteProjectMutation.isPending ? "Deleting..." : "Delete Project"}
                </Button>
            </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isTransferDialogOpen} onOpenChange={(open) => {
        setIsTransferDialogOpen(open)
        if (!open) setTransferTargetId("")
      }}>
        <DialogContent>
            <DialogHeader>
                <DialogTitle>Transfer Project Ownership</DialogTitle>
                <DialogDescription>
                    Select a project member to become the new owner of <strong>{project.name}</strong>. You will remain a member with admin role.
                </DialogDescription>
            </DialogHeader>
            <div className="py-4">
                <Label htmlFor="transfer-target">New Owner</Label>
                <Select value={transferTargetId} onValueChange={setTransferTargetId}>
                    <SelectTrigger className="mt-2">
                        <SelectValue placeholder="Select a member" />
                    </SelectTrigger>
                    <SelectContent>
                        {project.members
                            .filter(m => m.user_id !== project.owner_id)
                            .map(m => (
                                <SelectItem key={m.user_id} value={m.user_id}>
                                    {m.username || m.user_id} ({m.role})
                                </SelectItem>
                            ))
                        }
                    </SelectContent>
                </Select>
            </div>
            <DialogFooter>
                <Button variant="outline" onClick={() => setIsTransferDialogOpen(false)}>Cancel</Button>
                <Button
                    variant="destructive"
                    onClick={() => {
                        transferOwnershipMutation.mutate(
                            { id: projectId, newOwnerId: transferTargetId },
                            {
                                onSuccess: () => {
                                    toast.success("Ownership transferred successfully")
                                    setIsTransferDialogOpen(false)
                                    setTransferTargetId("")
                                },
                                onError: (error) => {
                                    toast.error("Failed to transfer ownership", {
                                        description: getErrorMessage(error)
                                    })
                                }
                            }
                        )
                    }}
                    disabled={!transferTargetId || transferOwnershipMutation.isPending}
                >
                    {transferOwnershipMutation.isPending ? "Transferring..." : "Transfer Ownership"}
                </Button>
            </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
