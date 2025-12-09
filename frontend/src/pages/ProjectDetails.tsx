import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getProject, getProjectScans, updateProject, rotateProjectApiKey, getTeams, getWaivers, deleteWaiver, getMe, updateProjectNotificationSettings, ProjectNotificationSettings, getProjectWebhooks, createProjectWebhook, deleteWebhook, WebhookCreate, getSystemSettings, exportProjectCsv, exportProjectSbom, inviteProjectMember, updateProjectMember, removeProjectMember } from '@/lib/api'
import { WebhookManager } from '@/components/WebhookManager'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { ArrowLeft, ShieldAlert, Activity, ShieldCheck, AlertTriangle, Copy, RefreshCw, Trash2, Filter, ArrowUpDown, Info, Download, UserPlus, UserMinus } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { Spinner } from '@/components/ui/spinner'
import { toast } from "sonner"
import { useState, useEffect, useMemo } from 'react'
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
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

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
  { id: 'trufflehog', label: 'TruffleHog (Secrets)', description: 'Scans for hardcoded secrets, passwords, and keys in the codebase.' },
];

export default function ProjectDetails() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  
  const [name, setName] = useState('')
  const [teamId, setTeamId] = useState<string | undefined>(undefined)
  const [retentionDays, setRetentionDays] = useState(90)
  const [analyzers, setAnalyzers] = useState<string[]>([])
  
  const [apiKey, setApiKey] = useState<string | null>(null)
  const [isApiKeyDialogOpen, setIsApiKeyDialogOpen] = useState(false)
  
  const [selectedBranches, setSelectedBranches] = useState<string[]>([])
  const [isBranchFilterOpen, setIsBranchFilterOpen] = useState(false)
  const [scanSortConfig, setScanSortConfig] = useState<{ key: string, direction: 'asc' | 'desc' } | null>(null)

  const { data: project, isLoading: isLoadingProject } = useQuery({
    queryKey: ['project', id],
    queryFn: () => getProject(id!),
    enabled: !!id
  })

  const { data: scans, isLoading: isLoadingScans } = useQuery({
    queryKey: ['project-scans', id],
    queryFn: () => getProjectScans(id!),
    enabled: !!id
  })

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: getTeams,
  })

  const { data: waivers } = useQuery({
    queryKey: ['waivers', id],
    queryFn: () => getWaivers(id!),
    enabled: !!id
  })

  const { data: user } = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
  })

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  })

  const { data: webhooks, isLoading: isLoadingWebhooks, refetch: refetchWebhooks } = useQuery({
    queryKey: ['projectWebhooks', id],
    queryFn: () => getProjectWebhooks(id!),
    enabled: !!id
  })

  const createWebhookMutation = useMutation({
    mutationFn: (data: WebhookCreate) => createProjectWebhook(id!, data),
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

  const [isInviteMemberOpen, setIsInviteMemberOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState("viewer")

  const inviteMemberMutation = useMutation({
    mutationFn: (data: { email: string, role: string }) => inviteProjectMember(id!, data.email, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', id] })
      setIsInviteMemberOpen(false)
      setInviteEmail("")
      setInviteRole("viewer")
      toast.success("Member invited successfully")
    },
    onError: (error: any) => {
      toast.error("Failed to invite member", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const updateMemberMutation = useMutation({
    mutationFn: (data: { userId: string, role: string }) => updateProjectMember(id!, data.userId, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', id] })
      toast.success("Member role updated")
    },
    onError: (error: any) => {
      toast.error("Failed to update member role", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => removeProjectMember(id!, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', id] })
      toast.success("Member removed")
    },
    onError: (error: any) => {
      toast.error("Failed to remove member", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const handleExportCsv = async () => {
    try {
      const blob = await exportProjectCsv(id!)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `project-${project?.name}-export.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      toast.error("Failed to export CSV")
    }
  }

  const handleExportSbom = async () => {
    try {
      const blob = await exportProjectSbom(id!)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `project-${project?.name}-sbom.json`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      toast.error("Failed to export SBOM")
    }
  }

  const [notificationPrefs, setNotificationPrefs] = useState<Record<string, string[]>>({})

  useEffect(() => {
    if (project && user) {
      let prefs: Record<string, string[]> = {}
      if (project.owner_id === user.id) {
        prefs = project.owner_notification_preferences || {}
      } else if (project.members) {
        const member = project.members.find(m => m.user_id === user.id)
        if (member) {
          prefs = member.notification_preferences || {}
        }
      }
      setNotificationPrefs(prefs)
    }
  }, [project, user])

  const updateNotificationSettingsMutation = useMutation({
    mutationFn: (settings: ProjectNotificationSettings) => updateProjectNotificationSettings(id!, settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', id] })
      toast.success("Notification settings updated")
    },
    onError: () => {
      toast.error("Failed to update notification settings")
    }
  })

  useEffect(() => {
    if (project) {
      setName(project.name)
      setTeamId(project.team_id || "none")
      setRetentionDays(project.retention_days || 90)
      setAnalyzers(project.active_analyzers || [])
    }
  }, [project])

  const updateProjectMutation = useMutation({
    mutationFn: (data: any) => updateProject(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', id] })
      toast.success("Project updated successfully")
    },
    onError: (error: any) => {
      toast.error("Failed to update project", {
        description: error.response?.data?.detail || "An error occurred"
      })
    }
  })

  const rotateKeyMutation = useMutation({
    mutationFn: () => rotateProjectApiKey(id!),
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

  const handleUpdate = (e: React.FormEvent) => {
    e.preventDefault()
    updateProjectMutation.mutate({
      name,
      team_id: teamId === "none" ? null : teamId,
      retention_days: retentionDays,
      active_analyzers: analyzers
    })
  }

  const toggleAnalyzer = (analyzerId: string) => {
    setAnalyzers(prev => 
      prev.includes(analyzerId)
        ? prev.filter(a => a !== analyzerId)
        : [...prev, analyzerId]
    )
  }

  const scanList = scans || []
  
  // Get all unique branches from all scans
  const allBranches = useMemo(() => {
      return Array.from(new Set(scanList.map(s => s.branch))).sort()
  }, [scanList])

  // Initialize selected branches when data loads
  useEffect(() => {
      if (allBranches.length > 0 && selectedBranches.length === 0) {
          setSelectedBranches(allBranches)
      }
  }, [allBranches])

  // Filter scans based on selection
  const filteredScans = useMemo(() => {
      if (selectedBranches.length === 0) return []
      return scanList.filter(s => selectedBranches.includes(s.branch))
  }, [scanList, selectedBranches])

  const tableScans = useMemo(() => {
      let result = [...filteredScans]
      if (scanSortConfig) {
          result.sort((a, b) => {
              let aValue = (a as any)[scanSortConfig.key]
              let bValue = (b as any)[scanSortConfig.key]

              if (scanSortConfig.key === 'critical') {
                  aValue = a.stats?.critical || 0
                  bValue = b.stats?.critical || 0
              } else if (scanSortConfig.key === 'high') {
                  aValue = a.stats?.high || 0
                  bValue = b.stats?.high || 0
              } else if (scanSortConfig.key === 'date') {
                  aValue = new Date(a.created_at).getTime()
                  bValue = new Date(b.created_at).getTime()
              }

              if (aValue < bValue) return scanSortConfig.direction === 'asc' ? -1 : 1
              if (aValue > bValue) return scanSortConfig.direction === 'asc' ? 1 : -1
              return 0
          })
      } else {
          // Default sort by date desc
          result.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      }
      return result
  }, [filteredScans, scanSortConfig])

  const requestScanSort = (key: string) => {
      let direction: 'asc' | 'desc' = 'asc'
      if (scanSortConfig && scanSortConfig.key === key && scanSortConfig.direction === 'asc') {
          direction = 'desc'
      }
      setScanSortConfig({ key, direction })
  }

  // Calculate Project Stats (Deduplicated across latest scan of each branch)
  const projectStats = useMemo(() => {
      if (!filteredScans.length) return null;

      // 1. Group by branch, get latest completed scan
      const latestScansByBranch: Record<string, any> = {};
      filteredScans.forEach(scan => {
          if (scan.status !== 'completed') return;
          if (!latestScansByBranch[scan.branch] || new Date(scan.created_at) > new Date(latestScansByBranch[scan.branch].created_at)) {
              latestScansByBranch[scan.branch] = scan;
          }
      });

      // 2. Collect unique findings
      const uniqueFindings = new Map(); // Key: finding.id + finding.component + finding.version
      const activeAnalyzers = project?.active_analyzers || [];
      
      Object.values(latestScansByBranch).forEach(scan => {
          if (!scan.findings_summary) return;
          scan.findings_summary.forEach((finding: any) => {
              // Check if finding is waived (either by backend or dynamically by frontend)
              let isWaived = finding.waived;
              
              if (!isWaived && waivers) {
                  // Dynamic check against active waivers
                  isWaived = waivers.some((waiver: any) => {
                      if (waiver.expiration_date && new Date(waiver.expiration_date) < new Date()) return false;
                      
                      let match = true;
                      if (waiver.finding_id && waiver.finding_id !== finding.id && waiver.finding_id !== finding.vuln_id) match = false;
                      if (match && waiver.package_name && waiver.package_name !== finding.component && waiver.package_name !== finding.pkg_name) match = false;
                      if (match && waiver.package_version && waiver.package_version !== finding.version && waiver.package_version !== finding.installed_version) match = false;
                      if (match && waiver.finding_type && waiver.finding_type !== finding.type) match = false;
                      
                      return match;
                  });
              }

              if (isWaived) return; 

              // Filter by active analyzers
              const findingScanners = finding.scanners || [];
              if (findingScanners.length > 0) {
                  const isActive = findingScanners.some((scanner: string) => activeAnalyzers.includes(scanner));
                  if (!isActive) return;
              }
              
              const key = `${finding.type}:${finding.id}:${finding.component}:${finding.version}`;
              if (!uniqueFindings.has(key)) {
                  uniqueFindings.set(key, finding);
              }
          });
      });

      // 3. Calculate Stats
      const stats: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
      const byCategory = { Security: 0, Compliance: 0, Quality: 0 };

      uniqueFindings.forEach(finding => {
          // Severity
          const severity = (finding.severity || 'UNKNOWN').toLowerCase();
          if (stats[severity] !== undefined) stats[severity]++;
          else stats.unknown++;

          // Category
          const type = finding.type || 'unknown';
          if (['vulnerability', 'secret', 'malware', 'typosquatting', 'sast'].includes(type)) byCategory.Security++;
          else if (['license', 'eol'].includes(type)) byCategory.Compliance++;
          else if (['outdated', 'quality'].includes(type)) byCategory.Quality++;
      });

      return { stats, byCategory };
  }, [filteredScans, waivers, project]);

  if (isLoadingProject || isLoadingScans) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Spinner size={48} />
      </div>
    )
  }

  if (!project) {
    return <div>Project not found</div>
  }

  // Trend Data Processing
  const sortedScans = [...filteredScans].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
  
  // Get unique branches (from filtered)
  const branches = Array.from(new Set(sortedScans.map(s => s.branch)))
  
  // Group by date
  const trendMap = new Map<string, any>()
  
  sortedScans.forEach(scan => {
      const date = new Date(scan.created_at).toLocaleDateString()
      const risk = (scan.stats?.critical || 0) + (scan.stats?.high || 0)
      
      if (!trendMap.has(date)) {
          trendMap.set(date, { date })
      }
      
      const entry = trendMap.get(date)
      // If multiple scans for same branch on same day, this will take the last one (due to sort order)
      entry[scan.branch] = risk
  })
  
  const trendData = Array.from(trendMap.values())
  const COLORS = ['#2563eb', '#16a34a', '#d97706', '#dc2626', '#9333ea', '#0891b2', '#ea580c', '#4f46e5'];

  const stats = projectStats?.stats || { critical: 0, high: 0, medium: 0, low: 0 };
  const pieData = [
      { name: 'Critical', value: stats.critical || 0, color: '#ef4444' },
      { name: 'High', value: stats.high || 0, color: '#f97316' },
      { name: 'Medium', value: stats.medium || 0, color: '#eab308' },
      { name: 'Low', value: stats.low || 0, color: '#3b82f6' },
  ].filter(d => d.value > 0);

  // Category Analysis
  const categoryData = Object.entries(projectStats?.byCategory || { Security: 0, Compliance: 0, Quality: 0 })
      .map(([name, value]) => ({ name, value }))
      .filter(d => d.value > 0);

  const toggleBranch = (branch: string) => {
      setSelectedBranches(prev => 
          prev.includes(branch) 
              ? prev.filter(b => b !== branch)
              : [...prev, branch]
      )
  }

  const toggleAllBranches = () => {
      if (selectedBranches.length === allBranches.length) {
          setSelectedBranches([])
      } else {
          setSelectedBranches(allBranches)
      }
  }

  const CATEGORY_COLORS: Record<string, string> = {
      Security: '#ef4444',
      Compliance: '#3b82f6',
      Quality: '#10b981'
  };

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
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link to="/dashboard">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h2 className="text-3xl font-bold tracking-tight">{project.name}</h2>
          <p className="text-muted-foreground text-sm">ID: {project._id}</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportCsv} className="gap-2">
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportSbom} className="gap-2">
              <Download className="h-4 w-4" />
              Export SBOM
            </Button>
            <Dialog open={isBranchFilterOpen} onOpenChange={setIsBranchFilterOpen}>
                <DialogTrigger asChild>
                    <Button variant="outline" className="gap-2">
                        <Filter className="h-4 w-4" />
                        Filter Branches
                        {selectedBranches.length < allBranches.length && (
                            <span className="bg-primary text-primary-foreground text-xs rounded-full w-5 h-5 flex items-center justify-center">
                                {selectedBranches.length}
                            </span>
                        )}
                    </Button>
                </DialogTrigger>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Filter Branches</DialogTitle>
                        <DialogDescription>
                            Select which branches to include in the analysis and charts.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="py-4 space-y-4">
                        <div className="flex items-center space-x-2 border-b pb-2">
                            <Checkbox 
                                id="select-all" 
                                checked={selectedBranches.length === allBranches.length && allBranches.length > 0}
                                onCheckedChange={toggleAllBranches}
                            />
                            <Label htmlFor="select-all" className="font-bold cursor-pointer">Select All</Label>
                        </div>
                        <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2">
                            {allBranches.map(branch => (
                                <div key={branch} className="flex items-center space-x-2">
                                    <Checkbox 
                                        id={`branch-${branch}`}
                                        checked={selectedBranches.includes(branch)}
                                        onCheckedChange={() => toggleBranch(branch)}
                                    />
                                    <Label htmlFor={`branch-${branch}`} className="cursor-pointer font-normal">{branch}</Label>
                                </div>
                            ))}
                            {allBranches.length === 0 && (
                                <p className="text-sm text-muted-foreground">No branches found.</p>
                            )}
                        </div>
                    </div>
                    <DialogFooter>
                        <Button onClick={() => setIsBranchFilterOpen(false)}>Done</Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="scans">Scans</TabsTrigger>
          <TabsTrigger value="waivers">Waivers</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Critical</CardTitle>
                <ShieldAlert className="h-4 w-4 text-destructive" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats.critical || 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">High</CardTitle>
                <Activity className="h-4 w-4 text-orange-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stats.high || 0}</div>
              </CardContent>
            </Card>
             <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Last Scan</CardTitle>
                <ShieldCheck className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-sm">
                    {project.last_scan_at ? new Date(project.last_scan_at).toLocaleString() : 'Never'}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Active Waivers</CardTitle>
                <ShieldCheck className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{waivers?.length || 0}</div>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
            <Card className="col-span-3">
                <CardHeader>
                    <CardTitle>Vulnerability Distribution</CardTitle>
                </CardHeader>
                <CardContent className="h-[300px]">
                    {pieData.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip />
                                <Legend />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="flex h-full items-center justify-center text-muted-foreground">
                            No vulnerabilities found
                        </div>
                    )}
                </CardContent>
            </Card>

            <Card className="col-span-4">
                <CardHeader>
                <CardTitle>Vulnerability Trend</CardTitle>
                </CardHeader>
                <CardContent className="pl-2">
                <div className="h-[300px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} />
                        <XAxis 
                        dataKey="date" 
                        stroke="#888888" 
                        fontSize={12} 
                        tickLine={false} 
                        axisLine={false} 
                        />
                        <YAxis
                        stroke="#888888"
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(value) => `${value}`}
                        />
                        <Tooltip 
                            contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                        />
                        <Legend />
                        {branches.map((branch, index) => (
                            <Line 
                                key={branch}
                                type="monotone" 
                                dataKey={branch} 
                                stroke={COLORS[index % COLORS.length]} 
                                strokeWidth={2} 
                                activeDot={{ r: 8 }} 
                                connectNulls
                            />
                        ))}
                    </LineChart>
                    </ResponsiveContainer>
                </div>
                </CardContent>
            </Card>
          </div>

          {categoryData.length > 0 && (
            <div className="grid gap-4 md:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle>Findings by Category</CardTitle>
                        <CardDescription>Based on latest scan of selected branches</CardDescription>
                    </CardHeader>
                    <CardContent className="h-[300px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={categoryData} layout="vertical" margin={{ left: 40 }}>
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                                <XAxis type="number" allowDecimals={false} />
                                <YAxis dataKey="name" type="category" width={100} />
                                <Tooltip />
                                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                    {categoryData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={CATEGORY_COLORS[entry.name] || '#8884d8'} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </CardContent>
                </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="scans">
          <Card>
            <CardHeader>
              <CardTitle>Scan History</CardTitle>
              <CardDescription>Showing scans for: {selectedBranches.length === allBranches.length ? 'All Branches' : selectedBranches.join(', ')}</CardDescription>
            </CardHeader>
            <CardContent>
                <div className="relative w-full overflow-auto">
                    <table className="w-full caption-bottom text-sm">
                        <thead className="[&_tr]:border-b">
                            <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestScanSort('date')}>
                                    <div className="flex items-center gap-1">Date {scanSortConfig?.key === 'date' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestScanSort('branch')}>
                                    <div className="flex items-center gap-1">Branch {scanSortConfig?.key === 'branch' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestScanSort('status')}>
                                    <div className="flex items-center gap-1">Status {scanSortConfig?.key === 'status' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestScanSort('critical')}>
                                    <div className="flex items-center gap-1">Critical {scanSortConfig?.key === 'critical' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestScanSort('high')}>
                                    <div className="flex items-center gap-1">High {scanSortConfig?.key === 'high' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                            </tr>
                        </thead>
                        <tbody className="[&_tr:last-child]:border-0">
                            {tableScans.map((scan) => (
                                <tr 
                                    key={scan._id} 
                                    className="border-b transition-colors hover:bg-muted/50 cursor-pointer"
                                    onClick={() => navigate(`/projects/${id}/scans/${scan._id}`)}
                                >
                                    <td className="p-4 align-middle">{new Date(scan.created_at).toLocaleString()}</td>
                                    <td className="p-4 align-middle">{scan.branch}</td>
                                    <td className="p-4 align-middle">{scan.status}</td>
                                    <td className="p-4 align-middle text-destructive font-bold">{scan.stats?.critical || 0}</td>
                                    <td className="p-4 align-middle text-orange-500 font-bold">{scan.stats?.high || 0}</td>
                                </tr>
                            ))}
                            {tableScans.length === 0 && (
                                <tr>
                                    <td colSpan={5} className="p-4 text-center text-muted-foreground">No scans found for selected branches.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </CardContent>
        </Card>
        </TabsContent>
        
        <TabsContent value="waivers">
            <WaiversTab projectId={id!} />
        </TabsContent>

        <TabsContent value="webhooks" className="space-y-4">
          <WebhookManager 
            webhooks={webhooks || []}
            isLoading={isLoadingWebhooks}
            onCreate={(data) => createWebhookMutation.mutateAsync(data)}
            onDelete={(id) => deleteWebhookMutation.mutateAsync(id)}
            title="Project Webhooks"
            description="Configure webhooks for this project."
          />
        </TabsContent>

        <TabsContent value="members" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Project Members</CardTitle>
                <CardDescription>Manage who has access to this project.</CardDescription>
              </div>
              <Dialog open={isInviteMemberOpen} onOpenChange={setIsInviteMemberOpen}>
                <DialogTrigger asChild>
                  <Button className="gap-2">
                    <UserPlus className="h-4 w-4" />
                    Invite Member
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Invite Member</DialogTitle>
                    <DialogDescription>Add a user to this project.</DialogDescription>
                  </DialogHeader>
                  <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                      <Label htmlFor="email">Email</Label>
                      <Input 
                        id="email" 
                        value={inviteEmail} 
                        onChange={(e) => setInviteEmail(e.target.value)} 
                        placeholder="user@example.com"
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="role">Role</Label>
                      <Select value={inviteRole} onValueChange={setInviteRole}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="viewer">Viewer</SelectItem>
                          <SelectItem value="editor">Editor</SelectItem>
                          <SelectItem value="admin">Admin</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button onClick={() => inviteMemberMutation.mutate({ email: inviteEmail, role: inviteRole })} disabled={inviteMemberMutation.isPending}>
                      {inviteMemberMutation.isPending ? <Spinner className="mr-2 h-4 w-4" /> : null}
                      Invite
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead className="w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {project.members?.map((member) => (
                    <TableRow key={member.user_id}>
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium">{member.username || 'Unknown'}</span>
                          <span className="text-xs text-muted-foreground">{member.user_id}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Select 
                          defaultValue={member.role} 
                          onValueChange={(value) => updateMemberMutation.mutate({ userId: member.user_id, role: value })}
                          disabled={member.user_id === project.owner_id}
                        >
                          <SelectTrigger className="w-[120px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="viewer">Viewer</SelectItem>
                            <SelectItem value="editor">Editor</SelectItem>
                            <SelectItem value="admin">Admin</SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        {member.user_id !== project.owner_id && (
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="text-destructive"
                            onClick={() => removeMemberMutation.mutate(member.user_id)}
                          >
                            <UserMinus className="h-4 w-4" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                  {(!project.members || project.members.length === 0) && (
                    <TableRow>
                      <TableCell colSpan={3} className="text-center text-muted-foreground">
                        No members found.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="settings" className="space-y-6">
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
                                    <div key={analyzer.id} className="flex items-center space-x-2">
                                        <Checkbox 
                                            id={`analyzer-${analyzer.id}`}
                                            checked={analyzers.includes(analyzer.id)}
                                            onCheckedChange={() => toggleAnalyzer(analyzer.id)}
                                        />
                                        <div className="flex items-center gap-2">
                                            <Label htmlFor={`analyzer-${analyzer.id}`} className="font-normal cursor-pointer">
                                                {analyzer.label}
                                            </Label>
                                            <div title={analyzer.description} className="cursor-help text-muted-foreground hover:text-foreground">
                                                <Info className="h-4 w-4" />
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                        <Button type="submit" disabled={updateProjectMutation.isPending}>
                            {updateProjectMutation.isPending ? <Spinner className="mr-2 h-4 w-4" /> : null}
                            Save Changes
                        </Button>
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
                    <Button 
                        onClick={() => updateNotificationSettingsMutation.mutate({ notification_preferences: notificationPrefs })}
                        disabled={updateNotificationSettingsMutation.isPending}
                    >
                        {updateNotificationSettingsMutation.isPending ? <Spinner className="mr-2 h-4 w-4" /> : null}
                        Save Notification Settings
                    </Button>
                </CardContent>
            </Card>

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
                            {rotateKeyMutation.isPending ? <Spinner className="mr-2 h-4 w-4" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                            Rotate Key
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </TabsContent>
      </Tabs>

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

function WaiversTab({ projectId }: { projectId: string }) {
    const queryClient = useQueryClient()
    const { data: waivers, isLoading } = useQuery({
        queryKey: ['waivers', projectId],
        queryFn: () => getWaivers(projectId)
    })
    
    const [searchQuery, setSearchQuery] = useState('')
    const [sortConfig, setSortConfig] = useState<{ key: string, direction: 'asc' | 'desc' } | null>(null)

    const deleteWaiverMutation = useMutation({
        mutationFn: deleteWaiver,
        onSuccess: () => {
            toast.success("Waiver deleted successfully")
            queryClient.invalidateQueries({ queryKey: ['waivers', projectId] })
        },
        onError: (error: any) => {
            toast.error("Failed to delete waiver", {
                description: error.response?.data?.detail || "An error occurred"
            })
        }
    })

    const filteredWaivers = useMemo(() => {
        if (!waivers) return []
        let result = [...waivers]
        
        if (searchQuery) {
            const lower = searchQuery.toLowerCase()
            result = result.filter((w: any) => 
                (w.package_name || '').toLowerCase().includes(lower) ||
                (w.reason || '').toLowerCase().includes(lower) ||
                (w.finding_id || '').toLowerCase().includes(lower)
            )
        }

        if (sortConfig) {
            result.sort((a: any, b: any) => {
                let aValue = a[sortConfig.key]
                let bValue = b[sortConfig.key]
                
                if (sortConfig.key === 'expires') {
                    aValue = a.expiration_date ? new Date(a.expiration_date).getTime() : 9999999999999
                    bValue = b.expiration_date ? new Date(b.expiration_date).getTime() : 9999999999999
                }

                if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1
                if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1
                return 0
            })
        }
        return result
    }, [waivers, searchQuery, sortConfig])

    const requestSort = (key: string) => {
        let direction: 'asc' | 'desc' = 'asc'
        if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
            direction = 'desc'
        }
        setSortConfig({ key, direction })
    }

    if (isLoading) {
        return <div className="flex justify-center p-8"><Spinner /></div>
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle>Active Waivers</CardTitle>
                <CardDescription>Manage exceptions for security findings.</CardDescription>
            </CardHeader>
            <CardContent>
                <div className="mb-4">
                    <Input 
                        placeholder="Search waivers..." 
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="max-w-sm"
                    />
                </div>
                <div className="relative w-full overflow-auto">
                    <table className="w-full caption-bottom text-sm">
                        <thead className="[&_tr]:border-b">
                            <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestSort('finding_id')}>
                                    <div className="flex items-center gap-1">Finding ID {sortConfig?.key === 'finding_id' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestSort('package_name')}>
                                    <div className="flex items-center gap-1">Package {sortConfig?.key === 'package_name' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestSort('reason')}>
                                    <div className="flex items-center gap-1">Reason {sortConfig?.key === 'reason' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground cursor-pointer" onClick={() => requestSort('expires')}>
                                    <div className="flex items-center gap-1">Expires {sortConfig?.key === 'expires' && <ArrowUpDown className="h-3 w-3" />}</div>
                                </th>
                                <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="[&_tr:last-child]:border-0">
                            {filteredWaivers.map((waiver: any) => (
                                <tr key={waiver._id} className="border-b transition-colors hover:bg-muted/50">
                                    <td className="p-4 align-middle font-mono">{waiver.finding_id || "Any"}</td>
                                    <td className="p-4 align-middle">
                                        {waiver.package_name} 
                                        {waiver.package_version && <span className="text-muted-foreground ml-1">v{waiver.package_version}</span>}
                                    </td>
                                    <td className="p-4 align-middle max-w-[300px] truncate" title={waiver.reason}>{waiver.reason}</td>
                                    <td className="p-4 align-middle">
                                        {waiver.expiration_date ? new Date(waiver.expiration_date).toLocaleDateString() : "Never"}
                                    </td>
                                    <td className="p-4 align-middle">
                                        <Button 
                                            variant="ghost" 
                                            size="icon" 
                                            className="text-destructive hover:text-destructive hover:bg-destructive/10"
                                            onClick={() => {
                                                if (confirm("Are you sure you want to delete this waiver?")) {
                                                    deleteWaiverMutation.mutate(waiver._id)
                                                }
                                            }}
                                            disabled={deleteWaiverMutation.isPending}
                                        >
                                            <Trash2 className="h-4 w-4" />
                                        </Button>
                                    </td>
                                </tr>
                            ))}
                            {filteredWaivers.length === 0 && (
                                <tr>
                                    <td colSpan={5} className="p-4 text-center text-muted-foreground">No active waivers found.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </CardContent>
        </Card>
    )
}
