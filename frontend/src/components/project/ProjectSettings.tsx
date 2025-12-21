import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { updateProject, rotateProjectApiKey, updateProjectNotificationSettings, ProjectNotificationSettings, getProjectWebhooks, createProjectWebhook, deleteWebhook, WebhookCreate, getTeams, getSystemSettings, Project, getProjectBranches, deleteProject, User, ProjectUpdate } from '@/lib/api'
import { useAuth } from '@/context/AuthContext'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { WebhookManager } from '@/components/WebhookManager'
import { AlertTriangle, RefreshCw, Copy, Trash2, Info } from 'lucide-react'
import { toast } from "sonner"
import { useNavigate } from 'react-router-dom'
import { AVAILABLE_ANALYZERS } from '@/lib/constants'
import { AxiosError } from 'axios'
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
  
  const [apiKey, setApiKey] = useState<string | null>(null)
  const [isApiKeyDialogOpen, setIsApiKeyDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [notificationPrefs, setNotificationPrefs] = useState<Record<string, string[]>>({})
  const [enforceNotificationSettings, setEnforceNotificationSettings] = useState(project.enforce_notification_settings || false)

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: () => getTeams(),
  })

  const { data: branches } = useQuery({
    queryKey: ['project-branches', projectId],
    queryFn: () => getProjectBranches(projectId),
  })

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  })

  const { data: webhooks, isLoading: isLoadingWebhooks, refetch: refetchWebhooks } = useQuery({
    queryKey: ['projectWebhooks', projectId],
    queryFn: () => getProjectWebhooks(projectId),
    enabled: !!projectId
  })

  useEffect(() => {
    if (project && user) {
      let prefs: Record<string, string[]> = {}
      const userId = user._id || user.id;
      
      setEnforceNotificationSettings(project.enforce_notification_settings || false)

      if (project.enforce_notification_settings) {
          prefs = project.owner_notification_preferences || {}
      } else {
          if (project.owner_id === userId) {
            prefs = project.owner_notification_preferences || {}
          } else if (project.members) {
            const member = project.members.find(m => m.user_id === userId)
            if (member) {
              prefs = member.notification_preferences || {}
            }
          }
      }
      setNotificationPrefs(prefs)
    }
  }, [project, user])

  const deleteProjectMutation = useMutation({
    mutationFn: () => deleteProject(projectId),
    onSuccess: () => {
      toast.success("Project Deleted", { description: "The project has been permanently deleted." })
      navigate('/projects')
    },
    onError: (error: AxiosError<any>) => {
      toast.error("Delete Failed", { description: error.response?.data?.detail || "Failed to delete project." })
    }
  })

  const updateProjectMutation = useMutation({
    mutationFn: (data: ProjectUpdate) => updateProject(projectId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      toast.success("Project updated successfully")
    },
    onError: (error: AxiosError<any>) => {
      toast.error("Failed to update project", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const updateNotificationSettingsMutation = useMutation({
    mutationFn: (settings: ProjectNotificationSettings) => updateProjectNotificationSettings(projectId, settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      toast.success("Notification settings updated")
    },
    onError: () => {
      toast.error("Failed to update notification settings")
    }
  })

  const rotateKeyMutation = useMutation({
    mutationFn: () => rotateProjectApiKey(projectId),
    onSuccess: (data) => {
      setApiKey(data.api_key)
      setIsApiKeyDialogOpen(true)
      toast.success("API Key rotated successfully")
    },
    onError: (error: AxiosError<any>) => {
      toast.error("Failed to rotate API key", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const createWebhookMutation = useMutation({
    mutationFn: (data: WebhookCreate) => createProjectWebhook(projectId, data),
    onSuccess: () => {
      refetchWebhooks()
    }
  })

  const deleteWebhookMutation = useMutation({
    mutationFn: deleteWebhook,
    onSuccess: () => {
      refetchWebhooks()
    }
  })

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
      gitlab_mr_comments_enabled: gitlabMrCommentsEnabled
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
                                <SelectItem key={team._id} value={team._id}>
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
                    {systemSettings?.retention_mode === 'global' ? (
                        <div className="p-3 bg-muted rounded-md text-sm border">
                            <p className="font-medium">Managed Globally</p>
                            <p className="text-muted-foreground mt-1">
                                {systemSettings.global_retention_days && systemSettings.global_retention_days > 0 
                                    ? `Data is retained for ${systemSettings.global_retention_days} days.` 
                                    : "Data retention is disabled (data is kept forever)."}
                            </p>
                        </div>
                    ) : (
                        <Input 
                            id="retention" 
                            type="number" 
                            min="1"
                            value={retentionDays} 
                            onChange={(e) => setRetentionDays(parseInt(e.target.value))} 
                        />
                    )}
                </div>
                <div className="grid gap-2">
                    <Label>Periodic Re-scanning</Label>
                    {systemSettings?.rescan_mode === 'global' ? (
                        <div className="p-3 bg-muted rounded-md text-sm border">
                            <p className="font-medium">Managed Globally</p>
                            <p className="text-muted-foreground mt-1">
                                {systemSettings.global_rescan_enabled 
                                    ? `Re-scanning is enabled (every ${systemSettings.global_rescan_interval} hours).` 
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
                                        onChange={(e) => setRescanInterval(parseInt(e.target.value))} 
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        How often to re-scan the project.
                                    </p>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {systemSettings?.gitlab_access_token && (
                    <div className="grid gap-2">
                        <Label>GitLab Integration</Label>
                        <div className="border rounded-md p-4 space-y-4">
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
                        </div>
                    </div>
                )}

                <div className="grid gap-2">
                    <Label>Active Analyzers</Label>
                    <div className="flex flex-col gap-2 border rounded-md p-4 max-h-[300px] overflow-y-auto">
                        {AVAILABLE_ANALYZERS.map((analyzer) => (
                            <div key={analyzer.id} className="flex items-start space-x-2 py-2">
                                <Checkbox 
                                    id={`analyzer-${analyzer.id}`}
                                    checked={analyzers.includes(analyzer.id)}
                                    onCheckedChange={() => toggleAnalyzer(analyzer.id)}
                                    className="mt-1"
                                />
                                <div className="flex flex-col gap-1">
                                    <Label htmlFor={`analyzer-${analyzer.id}`} className="font-medium cursor-pointer">
                                        {analyzer.label}
                                    </Label>
                                    <p className="text-xs text-muted-foreground">
                                        {analyzer.description}
                                    </p>
                                </div>
                            </div>
                        ))}
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

            <div className="border rounded-md">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead className="w-[300px]">Event</TableHead>
                            {['email', 'slack', 'mattermost'].map(channel => {
                                if (channel === 'email' && !systemSettings?.smtp_host) return null;
                                if (channel === 'slack' && !systemSettings?.slack_bot_token) return null;
                                if (channel === 'mattermost' && !systemSettings?.mattermost_url) return null;
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
                                    if (channel === 'email' && !systemSettings?.smtp_host) return null;
                                    if (channel === 'slack' && !systemSettings?.slack_bot_token) return null;
                                    if (channel === 'mattermost' && !systemSettings?.mattermost_url) return null;
                                    
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
                        notification_preferences: notificationPrefs,
                        enforce_notification_settings: enforceNotificationSettings
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
        onDelete={deleteWebhookMutation.mutateAsync}
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
    </div>
  )
}
