import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { updateProject, rotateProjectApiKey, updateProjectNotificationSettings, ProjectNotificationSettings, getProjectWebhooks, createProjectWebhook, deleteWebhook, WebhookCreate, getTeams, getSystemSettings, Project, getProjectBranches } from '@/lib/api'
import { useAuth } from '@/context/AuthContext'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { WebhookManager } from '@/components/WebhookManager'
import { AlertTriangle, RefreshCw, Copy } from 'lucide-react'
import { toast } from "sonner"
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

const AVAILABLE_ANALYZERS = [
  { id: 'end_of_life', label: 'End of Life (EOL)', description: 'Checks if packages have reached their End-of-Life date and are no longer supported.' },
  { id: 'os_malware', label: 'Open Source Malware', description: 'Checks packages against the Open Source Malware database for known malicious packages.' },
  { id: 'trivy', label: 'Trivy (Container/FS)', description: 'Scans container images and filesystems for vulnerabilities (CVEs) and misconfigurations.' },
  { id: 'osv', label: 'OSV (Open Source Vulnerabilities)', description: 'Checks dependencies against the Open Source Vulnerabilities (OSV) database.' },
  { id: 'deps_dev', label: 'Deps.dev (Google)', description: 'Queries Google\'s deps.dev API for security, license, and maintenance information.' },
  { id: 'license_compliance', label: 'License Compliance', description: 'Analyzes package licenses to ensure compliance with project policies.' },
  { id: 'grype', label: 'Grype (Anchore)', description: 'A vulnerability scanner for container images and filesystems, similar to Trivy.' },
  { id: 'outdated_packages', label: 'Outdated Packages', description: 'Identifies packages that are not on the latest version.' },
  { id: 'typosquatting', label: 'Typosquatting', description: 'Detects potential typosquatting attacks (packages with names similar to popular ones).' },
  { id: 'opengrep', label: 'OpenGrep (SAST)', description: 'Static Application Security Testing (SAST) tool to find security flaws in code.' },
  { id: 'kics', label: 'KICS (IaC)', description: 'Finds security vulnerabilities, compliance issues, and infrastructure misconfigurations in IaC.' },
  { id: 'bearer', label: 'Bearer (SAST/Data)', description: 'Static Application Security Testing (SAST) and Data Security tool.' },
  { id: 'trufflehog', label: 'TruffleHog (Secrets)', description: 'Scans for hardcoded secrets, passwords, and keys in the codebase.' },
];

interface ProjectSettingsProps {
  project: Project
  projectId: string
  user: any
}

export function ProjectSettings({ project, projectId, user }: ProjectSettingsProps) {
  const queryClient = useQueryClient()
  const { hasPermission } = useAuth()
  
  const [name, setName] = useState(project.name)
  const [teamId, setTeamId] = useState<string | undefined>(project.team_id || "none")
  const [retentionDays, setRetentionDays] = useState(project.retention_days || 90)
  const [analyzers, setAnalyzers] = useState<string[]>(project.active_analyzers || [])
  const [defaultBranch, setDefaultBranch] = useState<string | undefined>(project.default_branch)
  
  const [apiKey, setApiKey] = useState<string | null>(null)
  const [isApiKeyDialogOpen, setIsApiKeyDialogOpen] = useState(false)
  const [notificationPrefs, setNotificationPrefs] = useState<Record<string, string[]>>({})

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: getTeams,
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
      if (project.owner_id === userId) {
        prefs = project.owner_notification_preferences || {}
      } else if (project.members) {
        const member = project.members.find(m => m.user_id === userId)
        if (member) {
          prefs = member.notification_preferences || {}
        }
      }
      setNotificationPrefs(prefs)
    }
  }, [project, user])

  const updateProjectMutation = useMutation({
    mutationFn: (data: any) => updateProject(projectId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] })
      toast.success("Project updated successfully")
    },
    onError: (error: any) => {
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
    onError: (error: any) => {
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
      default_branch: defaultBranch === "none" ? null : defaultBranch
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
                    <Input 
                        id="retention" 
                        type="number" 
                        min="1"
                        value={retentionDays} 
                        onChange={(e) => setRetentionDays(parseInt(e.target.value))} 
                    />
                </div>
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
            <div className="grid gap-4">
                {['analysis_completed', 'vulnerability_found'].map(event => (
                    <div key={event} className="flex items-center justify-between border p-4 rounded-lg">
                        <div>
                            <div className="font-medium capitalize">{event.replace('_', ' ')}</div>
                            <div className="text-sm text-muted-foreground">
                                Receive notifications when {event.replace('_', ' ')} occurs.
                            </div>
                        </div>
                        <div className="flex items-center gap-4">
                            {['email', 'slack', 'mattermost'].filter(channel => {
                                if (channel === 'email') return !!systemSettings?.smtp_host;
                                if (channel === 'slack') return !!systemSettings?.slack_bot_token;
                                if (channel === 'mattermost') return !!systemSettings?.mattermost_url;
                                return false;
                            }).map(channel => (
                                <div key={channel} className="flex items-center space-x-2">
                                    <Checkbox 
                                        id={`${event}-${channel}`}
                                        checked={(notificationPrefs[event] || []).includes(channel)}
                                        onCheckedChange={() => toggleNotification(event, channel)}
                                    />
                                    <Label htmlFor={`${event}-${channel}`} className="capitalize cursor-pointer">
                                        {channel}
                                    </Label>
                                </div>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
            {hasPermission('project:update') && (
                <Button 
                    onClick={() => updateNotificationSettingsMutation.mutate({ notification_preferences: notificationPrefs })}
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
      />

      {hasPermission('project:update') && (
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
    </div>
  )
}
