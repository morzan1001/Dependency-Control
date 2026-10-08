import { useCallback, useMemo, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { useAppConfig } from '@/hooks/queries/use-system'
import { useTeams } from '@/hooks/queries/use-teams'
import { useClickOutside } from '@/hooks/use-click-outside'
import { projectKeys, useProjectBranches, useUpdateProjectNotifications } from '@/hooks/queries/use-projects'
import { useProjectWebhooks, useCreateProjectWebhook, useUpdateWebhook, useDeleteWebhook } from '@/hooks/queries/use-webhooks'
import { useGitLabInstances, useGitHubInstances } from '@/hooks/queries/use-instances'
import { Project, ProjectUpdate } from '@/types/project'
import { hasSettingsSchema, getSettingsSchema } from '@/lib/analyzer-settings-schemas'
import { AnalyzerSettingsDialog } from './AnalyzerSettingsDialog'
import type { TeamRef } from '@/types/team'
import { User } from '@/types/user'
import { cn, getErrorMessage } from '@/lib/utils'
import { memberPreferences, enforcedPreferences } from '@/lib/notification-preferences'
import { useAuth } from '@/context/useAuth'
import {
  isProjectAdmin,
  canUpdateProject,
  canDeleteProject,
  canRotateApiKey,
  canEnforceNotifications,
  canCreateProjectWebhook,
  canDeleteProjectWebhook, canUpdateProjectWebhook,
} from '@/lib/project-roles'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { WebhookManager } from '@/components/WebhookManager'
import { CryptoPolicyOverridePage } from '@/pages/project/CryptoPolicyOverridePage'
import { AlertTriangle, RefreshCw, Copy, Trash2, Info, Settings, Check, ChevronDown } from 'lucide-react'
import { toast } from "sonner"
import { useNavigate } from 'react-router-dom'
import { NOTIFICATION_CHANNELS, NOTIFICATION_EVENTS } from '@/lib/constants'
import { AnalyzerChecklist } from './AnalyzerChecklist'
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

interface TeamPickerProps {
  teams: TeamRef[]
  selectedIds: string[]
  onToggle: (id: string) => void
}

function TeamPicker({ teams, selectedIds, onToggle }: Readonly<TeamPickerProps>) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const close = useCallback(() => setOpen(false), [])
  useClickOutside(containerRef, close, open)

  const selectedNames = teams.filter((team) => selectedIds.includes(team.id)).map((team) => team.name)

  return (
    <div
      ref={containerRef}
      className="relative"
      onKeyDown={(event) => event.key === 'Escape' && close()}
    >
      <button
        type="button"
        id="teams"
        role="combobox"
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={() => setOpen(!open)}
        className="flex h-10 w-full items-center justify-between gap-2 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
      >
        <span className={cn('truncate text-left', selectedNames.length === 0 && 'text-muted-foreground')}>
          {selectedNames.length > 0 ? selectedNames.join(', ') : 'No Team'}
        </span>
        <ChevronDown className="h-4 w-4 shrink-0 opacity-50" />
      </button>

      {open && (
        <div className="absolute z-50 mt-1 w-full rounded-md border bg-popover text-popover-foreground shadow-md">
          <div role="listbox" aria-multiselectable className="max-h-64 overflow-y-auto p-1">
            {teams.map((team) => {
              const selected = selectedIds.includes(team.id)
              return (
                <button
                  key={team.id}
                  type="button"
                  role="option"
                  aria-selected={selected}
                  onClick={() => onToggle(team.id)}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground"
                >
                  <Check className={cn('h-4 w-4 shrink-0', selected ? 'opacity-100' : 'opacity-0')} />
                  <span className="truncate">{team.name}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export function ProjectSettings({ project, projectId, user }: Readonly<ProjectSettingsProps>) {
  const queryClient = useQueryClient()
  const { permissions } = useAuth()
  const navigate = useNavigate()

  const userId = user.id
  const canUpdate = canUpdateProject(project, userId, permissions)
  const canDelete = canDeleteProject(project, userId, permissions)
  const canRotateKey = canRotateApiKey(project, userId, permissions)
  const canEnforce = canEnforceNotifications(project, userId, permissions)
  const canCreateWh = canCreateProjectWebhook(project, userId, permissions)
  const canDeleteWh = canDeleteProjectWebhook(project, userId, permissions)
  const canUpdateWh = canUpdateProjectWebhook(project, userId, permissions)
  const canEditCryptoPolicy = isProjectAdmin(project, userId, permissions)
  const isSystemManager = permissions.includes('system:manage')
  const isMember = !!project.members?.some(m => m.user_id === userId)
  
  const [name, setName] = useState(project.name)
  const [teamIds, setTeamIds] = useState<string[]>(project.team_ids ?? [])
  const [retentionDays, setRetentionDays] = useState(project.retention_days || 90)
  const [retentionAction, setRetentionAction] = useState<string>(project.retention_action || 'delete')
  const [analyzers, setAnalyzers] = useState<string[]>(project.active_analyzers || [])
  const [defaultBranch, setDefaultBranch] = useState<string | undefined>(project.default_branch)
  const [rescanEnabled, setRescanEnabled] = useState<boolean | undefined>(project.rescan_enabled)
  const [rescanInterval, setRescanInterval] = useState<number | undefined>(project.rescan_interval)
  const [gitlabMrCommentsEnabled, setGitlabMrCommentsEnabled] = useState<boolean>(project.gitlab_mr_comments_enabled || false)
  const [gitlabInstanceId, setGitlabInstanceId] = useState<string | undefined>(project.gitlab_instance_id)
  const [gitlabProjectId, setGitlabProjectId] = useState<number | undefined>(project.gitlab_project_id)
  const [gitlabProjectPath, setGitlabProjectPath] = useState<string | undefined>(project.gitlab_project_path)
  const [githubPrCommentsEnabled, setGithubPrCommentsEnabled] = useState<boolean>(project.github_pr_comments_enabled || false)

  const [openSettingsAnalyzer, setOpenSettingsAnalyzer] = useState<string | null>(null)
  const [analyzerSettingsState, setAnalyzerSettingsState] = useState<Record<string, Record<string, unknown>>>(
    project.analyzer_settings || {}
  )

  const saveAnalyzerSettings = (analyzerId: string, values: Record<string, unknown>) => {
    const updated = { ...analyzerSettingsState, [analyzerId]: values }
    setAnalyzerSettingsState(updated)
    updateProjectMutation.mutate(
      { analyzer_settings: updated },
      { onSuccess: () => setOpenSettingsAnalyzer(null) }
    )
  }

  const [apiKey, setApiKey] = useState<string | null>(null)
  const [isApiKeyDialogOpen, setIsApiKeyDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [enforceNotificationSettings, setEnforceNotificationSettings] = useState(project.enforce_notification_settings || false)
  
  const [notificationPrefs, setNotificationPrefs] = useState<Record<string, string[]>>(() => {
    if (project.enforce_notification_settings) {
      return enforcedPreferences(project) || {};
    }

    const projectPrefs = memberPreferences(project, user.id);
    if (projectPrefs) {
      return projectPrefs;
    }
    return user.notification_preferences || {};
  })

  const { data: teams } = useTeams();
  const { data: branches } = useProjectBranches(projectId);
  const { data: appConfig } = useAppConfig();
  // A project without its own schedule runs on the global one, so that is what it shows.
  const effectiveRescanEnabled = (rescanEnabled ?? appConfig?.global_rescan_enabled) === true
  const { data: webhooks, isLoading: isLoadingWebhooks } = useProjectWebhooks(projectId);

  const { data: gitlabInstances } = useGitLabInstances({ active_only: true }, isSystemManager);
  const { data: githubInstances } = useGitHubInstances({ active_only: true }, isSystemManager);

  // Show only the config for the platform the project was sourced from (by *_instance_id).
  const gitlabSource: "gitlab" | "none" = project.gitlab_instance_id ? "gitlab" : "none";
  const gitlabBindingEditable = (gitlabInstances?.items?.length ?? 0) > 0;
  const projectSource: "gitlab" | "github" | "none" = project.github_instance_id
    ? "github"
    : gitlabSource;
  const linkedGithubInstance = project.github_instance_id
    ? githubInstances?.items.find((i) => i.id === project.github_instance_id)
    : undefined;

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
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
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


  const createWebhookMutation = useCreateProjectWebhook()
  const updateWebhookMutation = useUpdateWebhook()
  const deleteWebhookMutation = useDeleteWebhook()

  // An owning team the caller cannot see is still an owner, and leaving it out of the options
  // would have the whole-set save drop it without anyone choosing to.
  const teamOptions: TeamRef[] = useMemo(() => {
    const visible = (teams ?? []).map((team) => ({ id: team.id, name: team.name }))
    const unseen = (project.team_ids ?? [])
      .filter((id) => !visible.some((team) => team.id === id))
      .map((id) => ({ id, name: id }))
    return [...visible, ...unseen].sort((a, b) => a.name.localeCompare(b.name))
  }, [teams, project.team_ids])

  const toggleTeam = (id: string) =>
    setTeamIds((current) =>
      current.includes(id) ? current.filter((selected) => selected !== id) : [...current, id],
    )

  const handleUpdate = (e?: React.FormEvent) => {
    e?.preventDefault()
    updateProjectMutation.mutate({
      name,
      team_ids: teamIds,
      retention_days: retentionDays,
      retention_action: retentionAction as 'delete' | 'archive' | 'none',
      active_analyzers: analyzers,
      default_branch: defaultBranch ?? null,
      rescan_enabled: rescanEnabled,
      rescan_interval: rescanInterval,
      gitlab_mr_comments_enabled: gitlabMrCommentsEnabled,
      gitlab_instance_id: gitlabInstanceId || null,
      gitlab_project_id: gitlabProjectId || null,
      gitlab_project_path: gitlabProjectPath || null,
      github_pr_comments_enabled: githubPrCommentsEnabled,
    })
  }

  const clearGitlabBinding = () => {
    setGitlabInstanceId(undefined)
    setGitlabProjectId(undefined)
    setGitlabProjectPath(undefined)
  }

  const gitlabMrSwitch = (
    <div className="flex items-center justify-between">
      <div className="space-y-0.5">
        <Label htmlFor="gitlab-mr-comments" className="text-base">Merge Request Decoration</Label>
        <p className="text-sm text-muted-foreground">Post scan results as comments on GitLab Merge Requests.</p>
      </div>
      <Switch id="gitlab-mr-comments" checked={gitlabMrCommentsEnabled} onCheckedChange={setGitlabMrCommentsEnabled} />
    </div>
  )

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
                    <Label htmlFor="teams">Teams</Label>
                    <TeamPicker teams={teamOptions} selectedIds={teamIds} onToggle={toggleTeam} />
                    <p className="text-xs text-muted-foreground">
                        Every selected team's members can open this project, and it is listed under each of them.
                    </p>
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="defaultBranch">Default Branch</Label>
                    <Select value={defaultBranch || "none"} onValueChange={(val) => setDefaultBranch(val === "none" ? undefined : val)}>
                        <SelectTrigger id="defaultBranch">
                            <SelectValue placeholder="Select default branch" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="none">None (Show All)</SelectItem>
                            {branches?.map((branch) => (
                                <SelectItem key={branch.name} value={branch.name}>{branch.name}</SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                        This branch will be selected by default on the dashboard.
                    </p>
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="retention">Data Retention</Label>
                    {appConfig?.retention_mode === 'global' ? (
                        <div className="p-3 bg-muted rounded-md text-sm border">
                            <p className="font-medium">Managed Globally</p>
                            <p className="text-muted-foreground mt-1">
                                {appConfig.global_retention_days && appConfig.global_retention_days > 0
                                    ? `Data is retained for ${appConfig.global_retention_days} days (${
                                        { archive: 'archived to S3', none: 'kept forever', delete: 'deleted' }[appConfig.global_retention_action || 'delete']
                                      }).`
                                    : "Data retention is disabled (data is kept forever)."}
                            </p>
                        </div>
                    ) : (
                        <div className="border rounded-md p-4 space-y-4">
                            <div className="grid gap-2">
                                <Label htmlFor="retention">Retention Period (Days)</Label>
                                <Input
                                    id="retention"
                                    type="number"
                                    min="1"
                                    max="36500"
                                    value={retentionDays}
                                    onChange={(e) => setRetentionDays(Number.parseInt(e.target.value) || 90)}
                                />
                            </div>
                            <div className="grid gap-2">
                                <Label>Retention Action</Label>
                                <Select value={retentionAction} onValueChange={setRetentionAction}>
                                    <SelectTrigger>
                                        <SelectValue placeholder="Select action" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="delete">Delete</SelectItem>
                                        {appConfig?.archive_enabled && (
                                            <SelectItem value="archive">Archive to S3</SelectItem>
                                        )}
                                        <SelectItem value="none">None (Keep Forever)</SelectItem>
                                    </SelectContent>
                                </Select>
                                <p className="text-xs text-muted-foreground">
                                    Action to take when scan data exceeds the retention period.
                                </p>
                            </div>
                        </div>
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
                                    <Label htmlFor="rescanEnabled" className="text-base">Enable Re-scanning</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Automatically re-scan the latest SBOMs periodically.
                                    </p>
                                </div>
                                <Switch
                                    id="rescanEnabled"
                                    checked={effectiveRescanEnabled}
                                    onCheckedChange={(checked) => setRescanEnabled(checked)}
                                />
                            </div>
                            
                            {effectiveRescanEnabled && (
                                <div className="grid gap-2">
                                    <Label htmlFor="rescanInterval">Interval (Hours)</Label>
                                    <Input 
                                        id="rescanInterval" 
                                        type="number" 
                                        min="1"
                                        value={rescanInterval ?? appConfig?.global_rescan_interval ?? 24} 
                                        onChange={(e) => setRescanInterval(Number.parseInt(e.target.value) || 24)} 
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        How often to re-scan the project.
                                    </p>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {projectSource === "github" && (
                    <div className="grid gap-2">
                        <Label>GitHub Integration</Label>
                        <div className="border rounded-md p-4 space-y-2 text-sm">
                            <div className="grid grid-cols-[150px_1fr] gap-x-4 gap-y-1">
                                <span className="text-muted-foreground">Instance</span>
                                <span className="font-mono">
                                    {linkedGithubInstance
                                        ? `${linkedGithubInstance.name} (${linkedGithubInstance.url})`
                                        : project.github_instance_id}
                                </span>
                                {project.github_repository_path && (
                                    <>
                                        <span className="text-muted-foreground">Repository</span>
                                        <span className="font-mono">{project.github_repository_path}</span>
                                    </>
                                )}
                                {project.github_repository_id && (
                                    <>
                                        <span className="text-muted-foreground">Repository ID</span>
                                        <span className="font-mono">{project.github_repository_id}</span>
                                    </>
                                )}
                            </div>
                            <p className="text-xs text-muted-foreground pt-2">
                                This project was created from a GitHub instance. The link is managed by the GitHub Actions OIDC trust and isn't editable here.
                            </p>

                            <div className="flex items-center justify-between pt-2 border-t">
                                <div className="space-y-0.5">
                                    <Label htmlFor="github-pr-comments" className="text-base">Pull Request Decoration</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Post scan results as comments on GitHub Pull Requests.
                                    </p>
                                </div>
                                <Switch
                                    id="github-pr-comments"
                                    checked={githubPrCommentsEnabled}
                                    onCheckedChange={setGithubPrCommentsEnabled}
                                />
                            </div>
                        </div>
                    </div>
                )}

                {projectSource === "gitlab" && !gitlabBindingEditable && (
                    <div className="grid gap-2">
                        <Label>GitLab Integration</Label>
                        <div className="border rounded-md p-4 space-y-2 text-sm">
                            {gitlabInstanceId ? (
                                <>
                                    <div className="grid grid-cols-[150px_1fr] gap-x-4 gap-y-1">
                                        <span className="text-muted-foreground">Instance</span>
                                        <span className="font-mono">{gitlabInstanceId}</span>
                                        <span className="text-muted-foreground">Project ID</span>
                                        <span className="font-mono">{gitlabProjectId}</span>
                                        {gitlabProjectPath && (
                                            <>
                                                <span className="text-muted-foreground">Project Path</span>
                                                <span className="font-mono">{gitlabProjectPath}</span>
                                            </>
                                        )}
                                    </div>
                                    <p className="text-xs text-muted-foreground pt-2">
                                        Only administrators can change this link.
                                    </p>
                                    {canUpdate && (
                                        <Button type="button" variant="outline" size="sm" onClick={clearGitlabBinding}>
                                            Remove GitLab link
                                        </Button>
                                    )}
                                    <div className="pt-2 border-t">{gitlabMrSwitch}</div>
                                </>
                            ) : (
                                <p className="text-muted-foreground">The GitLab link is removed when you save.</p>
                            )}
                        </div>
                    </div>
                )}

                {(projectSource === "gitlab" || projectSource === "none") && gitlabBindingEditable && (
                    <div className="grid gap-2">
                        <Label>GitLab Integration</Label>
                        <div className="border rounded-md p-4 space-y-4">
                            <div className="grid gap-2">
                                <Label htmlFor="gitlab-instance">GitLab Instance</Label>
                                <Select
                                    value={gitlabInstanceId || "none"}
                                    onValueChange={(value) => (value === "none" ? clearGitlabBinding() : setGitlabInstanceId(value))}
                                >
                                    <SelectTrigger id="gitlab-instance">
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
                                            onChange={(e) => setGitlabProjectId(Number.parseInt(e.target.value) || undefined)}
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
                                            For display purposes only. Taken from GitLab when the binding is set or changed.
                                        </p>
                                    </div>

                                    {gitlabMrSwitch}
                                </>
                            )}
                        </div>
                    </div>
                )}

                <div className="grid gap-2">
                    <Label>Active Analyzers</Label>
                    <AnalyzerChecklist
                        idPrefix="settings-analyzer"
                        selected={analyzers}
                        onToggle={toggleAnalyzer}
                        className="max-h-[300px]"
                        renderAction={(analyzerId) => hasSettingsSchema(analyzerId) && analyzers.includes(analyzerId) && canUpdate && (
                            <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                className="ml-auto h-7 px-2 text-xs"
                                onClick={() => setOpenSettingsAnalyzer(analyzerId)}
                            >
                                <Settings className="h-3.5 w-3.5 mr-1" />
                                Configure
                            </Button>
                        )}
                    />
                </div>
                {canUpdate && (
                    <Button type="submit" disabled={updateProjectMutation.isPending}>
                        {updateProjectMutation.isPending ? "Saving..." : "Save Changes"}
                    </Button>
                )}
            </form>
        </CardContent>
      </Card>

      {openSettingsAnalyzer && (() => {
        const schema = getSettingsSchema(openSettingsAnalyzer)
        if (!schema) return null
        const currentValues = analyzerSettingsState[openSettingsAnalyzer] || {}
        return (
          <AnalyzerSettingsDialog
            // Remount on analyzer switch so internal state re-initializes from currentValues.
            key={openSettingsAnalyzer}
            open={true}
            onOpenChange={(isOpen) => { if (!isOpen) setOpenSettingsAnalyzer(null) }}
            schema={schema}
            currentValues={currentValues}
            onSave={(values) => saveAnalyzerSettings(openSettingsAnalyzer, values)}
            isSaving={updateProjectMutation.isPending}
            canEdit={canUpdate}
          />
        )
      })()}

      <CryptoPolicyOverridePage projectId={projectId} canEdit={canEditCryptoPolicy} />

      <Card>
        <CardHeader>
            <CardTitle>Notification Settings</CardTitle>
            <CardDescription>Configure how you want to be notified about project events.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
            {canEnforce && (
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

            {enforceNotificationSettings && !canEnforce && (
                <div className="flex items-center gap-2 p-4 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900">
                    <Info className="h-4 w-4" />
                    <p>Notification settings are currently enforced by the project administrator. You cannot modify them.</p>
                </div>
            )}

            {!enforceNotificationSettings && (() => {
                const hasProjectPrefs = !!memberPreferences(project, user.id);
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
                            {NOTIFICATION_CHANNELS.filter(c => appConfig?.notifications[c.id]).map(channel => (
                                <TableHead key={channel.id} className="capitalize text-center">{channel.label}</TableHead>
                            ))}
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {NOTIFICATION_EVENTS.map(event => (
                            <TableRow key={event.id} className={enforceNotificationSettings && !canEnforce ? 'opacity-60' : ''}>
                                <TableCell>
                                    <div className="font-medium">{event.label}</div>
                                    <div className="text-xs text-muted-foreground">{event.description}</div>
                                </TableCell>
                                {NOTIFICATION_CHANNELS.filter(c => appConfig?.notifications[c.id]).map(channel => (
                                    <TableCell key={channel.id} className="text-center">
                                        <div className="flex justify-center">
                                            <Checkbox
                                                id={`${event.id}-${channel.id}`}
                                                checked={(notificationPrefs[event.id] || []).includes(channel.id)}
                                                onCheckedChange={() => toggleNotification(event.id, channel.id)}
                                                disabled={enforceNotificationSettings && !canEnforce}
                                            />
                                        </div>
                                    </TableCell>
                                ))}
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </div>
            {(isMember || canEnforce) && (
                <Button
                    onClick={() => updateNotificationSettingsMutation.mutate({
                        id: project.id,
                        settings: {
                            // Every event is sent, so an all-unchecked matrix is stored as a mute rather than as no override.
                            notification_preferences: {
                                ...Object.fromEntries(NOTIFICATION_EVENTS.map(event => [event.id, []])),
                                ...notificationPrefs,
                            },
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
        onCreate={data => createWebhookMutation.mutateAsync({ projectId, data })}
        onUpdate={(id, data) => updateWebhookMutation.mutateAsync({ id, data })}
        onDelete={id => deleteWebhookMutation.mutateAsync(id)}
        createPermission={canCreateWh}
        deletePermission={canDeleteWh}
        updatePermission={canUpdateWh}
      />

      {(canUpdate || canDelete || canRotateKey) && (
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
                {canRotateKey && (
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

                {canDelete && (
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

    </div>
  )
}
