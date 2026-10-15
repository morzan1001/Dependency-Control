import { useCallback, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { projectApi } from '@/api/projects'
import { useAppConfig, useNotificationChannels } from '@/hooks/queries/use-system'
import { useTeams } from '@/hooks/queries/use-teams'
import { useClickOutside } from '@/hooks/use-click-outside'
import { useDialogState, type DialogState } from '@/hooks/use-dialog-state'
import { projectKeys, useProjectBranches, useUpdateProjectNotifications } from '@/hooks/queries/use-projects'
import { useProjectWebhooks, useCreateProjectWebhook, useUpdateWebhook, useDeleteWebhook } from '@/hooks/queries/use-webhooks'
import { useGitLabInstances, useGitHubInstances } from '@/hooks/queries/use-instances'
import { Project, ProjectUpdate } from '@/types/project'
import { hasSettingsSchema, getSettingsSchema } from '@/lib/analyzer-settings-schemas'
import { AnalyzerSettingsDialog } from './AnalyzerSettingsDialog'
import type { TeamRef } from '@/types/team'
import { User } from '@/types/user'
import { cn, toggle } from '@/lib/utils'
import { memberPreferences, enforcedPreferences, withMutedEvents } from '@/lib/notification-preferences'
import { useAuth } from '@/context/useAuth'
import {
  isProjectAdmin,
  canDeleteProject,
  canCreateProjectWebhook,
  canDeleteProjectWebhook, canUpdateProjectWebhook,
} from '@/lib/project-roles'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { CopyField } from '@/components/ui/copy-field'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { WebhookManager } from '@/components/WebhookManager'
import { NotificationMatrix } from '@/components/profile/NotificationMatrix'
import { CryptoPolicyOverridePage } from '@/pages/project/CryptoPolicyOverridePage'
import { AlertTriangle, RefreshCw, Trash2, Info, Settings, Check, ChevronDown } from 'lucide-react'
import { toast } from "sonner"
import { useNavigate } from 'react-router-dom'
import { AnalyzerChecklist } from './AnalyzerChecklist'
import { DEFAULT_RESCAN_HOURS, DEFAULT_RETENTION_DAYS, ManagedGlobally, RescanFields, RetentionFields } from './RetentionRescanFields'
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
      className="relative min-w-0"
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

function settingsForm(project: Project) {
  return {
    name: project.name,
    team_ids: project.team_ids ?? [],
    retention_days: project.retention_days || DEFAULT_RETENTION_DAYS,
    retention_action: project.retention_action || 'delete',
    active_analyzers: project.active_analyzers || [],
    default_branch: project.default_branch,
    rescan_enabled: project.rescan_enabled,
    rescan_interval: project.rescan_interval,
    gitlab_mr_comments_enabled: project.gitlab_mr_comments_enabled || false,
    gitlab_instance_id: project.gitlab_instance_id,
    gitlab_project_id: project.gitlab_project_id,
    gitlab_project_path: project.gitlab_project_path,
    github_pr_comments_enabled: project.github_pr_comments_enabled || false,
  }
}

type SettingsForm = ReturnType<typeof settingsForm>

interface DangerActionProps {
  title: string
  description: string
  label: string
  pendingLabel: string
  icon: ReactNode
  confirmation: ReactNode
  dialog: DialogState
  isPending: boolean
  onConfirm: () => void
}

function DangerAction({ title, description, label, pendingLabel, icon, confirmation, dialog, isPending, onConfirm }: Readonly<DangerActionProps>) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
      <div>
        <div className="font-medium">{title}</div>
        <div className="text-sm text-muted-foreground">{description}</div>
      </div>
      <Button variant="destructive" onClick={dialog.openDialog}>
        {icon}
        {label}
      </Button>
      <Dialog open={dialog.open} onOpenChange={dialog.setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{confirmation}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={dialog.closeDialog}>Cancel</Button>
            <Button variant="destructive" onClick={onConfirm} disabled={isPending}>
              {isPending ? pendingLabel : label}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export function ProjectSettings({ project, projectId, user }: Readonly<ProjectSettingsProps>) {
  const queryClient = useQueryClient()
  const { permissions } = useAuth()
  const navigate = useNavigate()

  const userId = user.id
  const isAdmin = isProjectAdmin(project, userId, permissions)
  const canDelete = canDeleteProject(project, userId, permissions)
  const canCreateWh = canCreateProjectWebhook(project, userId, permissions)
  const canDeleteWh = canDeleteProjectWebhook(project, userId, permissions)
  const canUpdateWh = canUpdateProjectWebhook(project, userId, permissions)
  const isSystemManager = permissions.includes('system:manage')
  const isMember = !!project.members?.some(m => m.user_id === userId)
  
  const [form, setForm] = useState(() => settingsForm(project))
  const set = (patch: Partial<SettingsForm>) => setForm((current) => ({ ...current, ...patch }))

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
  const rotateDialog = useDialogState()
  const deleteDialog = useDialogState()
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
  const notificationChannels = useNotificationChannels();
  // A project without its own schedule runs on the global one, so that is what it shows.
  const effectiveRescanEnabled = (form.rescan_enabled ?? appConfig?.global_rescan_enabled) === true
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
    meta: { errorTitle: "Failed to delete project" },
  })

  const updateProjectMutation = useMutation({
    mutationFn: (data: ProjectUpdate) => projectApi.update(projectId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(projectId) })
      toast.success("Project updated successfully")
    },
    meta: { errorTitle: "Failed to update project" },
  })

  const updateNotificationSettingsMutation = useUpdateProjectNotifications({ errorTitle: "Failed to update notification settings" })

  const rotateKeyMutation = useMutation({
    mutationFn: () => projectApi.rotateApiKey(projectId),
    onSuccess: (data) => {
      rotateDialog.closeDialog()
      setApiKey(data.api_key)
      setIsApiKeyDialogOpen(true)
      toast.success("API Key rotated successfully")
    },
    meta: { errorTitle: "Failed to rotate API key" },
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

  const handleUpdate = (e?: React.FormEvent) => {
    e?.preventDefault()
    updateProjectMutation.mutate({
      ...form,
      default_branch: form.default_branch ?? null,
      gitlab_instance_id: form.gitlab_instance_id || null,
      gitlab_project_id: form.gitlab_project_id || null,
      gitlab_project_path: form.gitlab_project_path || null,
    })
  }

  const clearGitlabBinding = () =>
    set({ gitlab_instance_id: undefined, gitlab_project_id: undefined, gitlab_project_path: undefined })

  const gitlabMrSwitch = (
    <div className="flex items-center justify-between">
      <div className="space-y-0.5">
        <Label htmlFor="gitlab-mr-comments" className="text-base">Merge Request Decoration</Label>
        <p className="text-sm text-muted-foreground">Post scan results as comments on GitLab Merge Requests.</p>
      </div>
      <Switch
        id="gitlab-mr-comments"
        checked={form.gitlab_mr_comments_enabled}
        onCheckedChange={(gitlab_mr_comments_enabled) => set({ gitlab_mr_comments_enabled })}
      />
    </div>
  )

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
                    <Input id="name" value={form.name} onChange={(e) => set({ name: e.target.value })} />
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="teams">Teams</Label>
                    <TeamPicker
                        teams={teamOptions}
                        selectedIds={form.team_ids}
                        onToggle={(id) => set({ team_ids: toggle(form.team_ids, id) })}
                    />
                    <p className="text-xs text-muted-foreground">
                        Every selected team's members can open this project, and it is listed under each of them.
                    </p>
                </div>
                <div className="grid gap-2">
                    <Label htmlFor="defaultBranch">Default Branch</Label>
                    <Select value={form.default_branch || "none"} onValueChange={(val) => set({ default_branch: val === "none" ? undefined : val })}>
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
                <RetentionFields
                    days={form.retention_days}
                    action={form.retention_action}
                    onChange={set}
                    appConfig={appConfig}
                />
                <div className="grid gap-2">
                    <Label>Periodic Re-scanning</Label>
                    {appConfig?.rescan_mode === 'global' ? (
                        <ManagedGlobally>
                            {appConfig.global_rescan_enabled
                                ? `Re-scanning is enabled (every ${appConfig.global_rescan_interval} hours).`
                                : "Re-scanning is disabled globally."}
                        </ManagedGlobally>
                    ) : (
                        <RescanFields
                            enabled={effectiveRescanEnabled}
                            interval={form.rescan_interval ?? appConfig?.global_rescan_interval ?? DEFAULT_RESCAN_HOURS}
                            onEnabledChange={(rescan_enabled) => set({ rescan_enabled })}
                            onIntervalChange={(rescan_interval) => set({ rescan_interval })}
                            description="Automatically re-scan the latest SBOMs periodically."
                        />
                    )}
                </div>

                {projectSource === "github" && (
                    <div className="grid gap-2">
                        <Label>GitHub Integration</Label>
                        <div className="border rounded-md p-4 space-y-2 text-sm">
                            <div className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[150px_1fr]">
                                <span className="text-muted-foreground">Instance</span>
                                <span className="font-mono wrap-anywhere">
                                    {linkedGithubInstance
                                        ? `${linkedGithubInstance.name} (${linkedGithubInstance.url})`
                                        : project.github_instance_id}
                                </span>
                                {project.github_repository_path && (
                                    <>
                                        <span className="text-muted-foreground">Repository</span>
                                        <span className="font-mono wrap-anywhere">{project.github_repository_path}</span>
                                    </>
                                )}
                                {project.github_repository_id && (
                                    <>
                                        <span className="text-muted-foreground">Repository ID</span>
                                        <span className="font-mono wrap-anywhere">{project.github_repository_id}</span>
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
                                    checked={form.github_pr_comments_enabled}
                                    onCheckedChange={(github_pr_comments_enabled) => set({ github_pr_comments_enabled })}
                                />
                            </div>
                        </div>
                    </div>
                )}

                {projectSource === "gitlab" && !gitlabBindingEditable && (
                    <div className="grid gap-2">
                        <Label>GitLab Integration</Label>
                        <div className="border rounded-md p-4 space-y-2 text-sm">
                            {form.gitlab_instance_id ? (
                                <>
                                    <div className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[150px_1fr]">
                                        <span className="text-muted-foreground">Instance</span>
                                        <span className="font-mono wrap-anywhere">{form.gitlab_instance_id}</span>
                                        <span className="text-muted-foreground">Project ID</span>
                                        <span className="font-mono wrap-anywhere">{form.gitlab_project_id}</span>
                                        {form.gitlab_project_path && (
                                            <>
                                                <span className="text-muted-foreground">Project Path</span>
                                                <span className="font-mono wrap-anywhere">{form.gitlab_project_path}</span>
                                            </>
                                        )}
                                    </div>
                                    <p className="text-xs text-muted-foreground pt-2">
                                        Only administrators can change this link.
                                    </p>
                                    {isAdmin && (
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
                        <div className="border rounded-md p-4 space-y-4 min-w-0">
                            <div className="grid gap-2">
                                <Label htmlFor="gitlab-instance">GitLab Instance</Label>
                                <Select
                                    value={form.gitlab_instance_id || "none"}
                                    onValueChange={(value) => (value === "none" ? clearGitlabBinding() : set({ gitlab_instance_id: value }))}
                                >
                                    <SelectTrigger id="gitlab-instance" className="min-w-0 text-left">
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

                            {form.gitlab_instance_id && (
                                <>
                                    <div className="grid gap-2">
                                        <Label htmlFor="gitlab-project-id">GitLab Project ID</Label>
                                        <Input
                                            id="gitlab-project-id"
                                            type="number"
                                            placeholder="12345"
                                            value={form.gitlab_project_id || ''}
                                            onChange={(e) => set({ gitlab_project_id: Number.parseInt(e.target.value) || undefined })}
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
                                            value={form.gitlab_project_path || ''}
                                            onChange={(e) => set({ gitlab_project_path: e.target.value || undefined })}
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
                        selected={form.active_analyzers}
                        onToggle={(analyzerId) => set({ active_analyzers: toggle(form.active_analyzers, analyzerId) })}
                        className="max-h-[300px]"
                        renderAction={(analyzerId) => hasSettingsSchema(analyzerId) && form.active_analyzers.includes(analyzerId) && isAdmin && (
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
                {isAdmin && (
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
            canEdit={isAdmin}
          />
        )
      })()}

      <CryptoPolicyOverridePage projectId={projectId} canEdit={isAdmin} />

      <Card>
        <CardHeader>
            <CardTitle>Notification Settings</CardTitle>
            <CardDescription>Configure how you want to be notified about project events.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
            {isAdmin && (
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

            {enforceNotificationSettings && !isAdmin && (
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

            <NotificationMatrix
                value={notificationPrefs}
                onChange={setNotificationPrefs}
                channels={notificationChannels}
                disabled={enforceNotificationSettings && !isAdmin}
            />
            {(isMember || isAdmin) && (
                <Button
                    onClick={() => updateNotificationSettingsMutation.mutate({
                        id: project.id,
                        settings: {
                            notification_preferences: withMutedEvents(notificationPrefs),
                            enforce_notification_settings: enforceNotificationSettings
                        }
                    }, {
                        onSuccess: () => toast.success("Notification settings updated"),
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

      {(isAdmin || canDelete) && (
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
                {isAdmin && (
                    <DangerAction
                        title="Rotate API Key"
                        description="Invalidate the current API key and generate a new one."
                        label="Rotate Key"
                        pendingLabel="Rotating..."
                        icon={<RefreshCw className="mr-2 h-4 w-4" />}
                        confirmation={<>Are you sure you want to rotate the API key of <strong>{project.name}</strong>? The current key stops working at once, so every pipeline that still sends it fails until it gets the new one.</>}
                        dialog={rotateDialog}
                        isPending={rotateKeyMutation.isPending}
                        onConfirm={() => rotateKeyMutation.mutate()}
                    />
                )}

                {canDelete && (
                    <DangerAction
                        title="Delete Project"
                        description="Permanently delete this project and all its data. This action cannot be undone."
                        label="Delete Project"
                        pendingLabel="Deleting..."
                        icon={<Trash2 className="mr-2 h-4 w-4" />}
                        confirmation={<>Are you sure you want to delete this project? This action cannot be undone and will permanently remove all scans, findings, and settings associated with <strong>{project.name}</strong>.</>}
                        dialog={deleteDialog}
                        isPending={deleteProjectMutation.isPending}
                        onConfirm={() => deleteProjectMutation.mutate()}
                    />
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
            <CopyField value={apiKey || ''} what="API key" />
            <DialogFooter>
                <Button onClick={() => setIsApiKeyDialogOpen(false)}>Close</Button>
            </DialogFooter>
        </DialogContent>
      </Dialog>

    </div>
  )
}
