import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getScan, getProject } from '@/lib/api'
import { FindingsTable } from '@/components/FindingsTable'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { ArrowLeft, GitBranch, GitCommit, ExternalLink, ShieldAlert, Calendar, CheckCircle } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'

export default function ScanDetails() {
  const { projectId, scanId } = useParams<{ projectId: string, scanId: string }>()

  const { data: scan, isLoading: isScanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId
  })

  const { data: project, isLoading: isProjectLoading } = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => getProject(projectId!),
    enabled: !!projectId
  })

  if (isScanLoading || isProjectLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10 rounded-md" />
          <div className="space-y-2">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
        <div className="space-y-4">
          <Skeleton className="h-10 w-full max-w-md" />
          <Skeleton className="h-[400px] rounded-xl" />
        </div>
      </div>
    )
  }

  if (!scan || !project) {
    return <div>No results found</div>
  }

  const activeAnalyzers = project.active_analyzers || [];
  const showSecurity = activeAnalyzers.some(a => ['trivy', 'grype', 'osv', 'os_malware', 'typosquatting', 'deps_dev'].includes(a));
  const showSecrets = activeAnalyzers.includes('trufflehog');
  const showSast = activeAnalyzers.some(a => ['opengrep', 'kics', 'bearer'].includes(a));
  const showCompliance = activeAnalyzers.some(a => ['trivy', 'license_compliance', 'end_of_life'].includes(a));
  const showQuality = activeAnalyzers.includes('outdated_packages');

  const stats = scan.stats || { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  
  const severityData = [
      { name: 'Critical', value: stats.critical, color: '#ef4444' },
      { name: 'High', value: stats.high, color: '#f97316' },
      { name: 'Medium', value: stats.medium, color: '#eab308' },
      { name: 'Low', value: stats.low, color: '#3b82f6' },
      { name: 'Info', value: stats.info, color: '#60a5fa' },
      { name: 'Unknown', value: stats.unknown, color: '#9ca3af' },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link to={`/projects/${projectId}`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h2 className="text-3xl font-bold tracking-tight">
            {scan.pipeline_iid ? `Pipeline #${scan.pipeline_iid}` : 'Scan Details'}
          </h2>
          <p className="text-muted-foreground text-sm">ID: {scanId}</p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
          <Card>
                <CardHeader>
                    <CardTitle>Scan Metadata</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Status</span>
                            <div>
                                <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'}>
                                    {scan.status}
                                </Badge>
                            </div>
                        </div>
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Branch</span>
                            <div className="flex items-center gap-2">
                                <GitBranch className="h-4 w-4" />
                                <span className="font-medium">{scan.branch}</span>
                            </div>
                        </div>
                        {scan.commit_hash && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Commit</span>
                                <div className="flex items-center gap-2">
                                    <GitCommit className="h-4 w-4" />
                                    <span className="font-medium font-mono text-xs">{scan.commit_hash.substring(0, 7)}</span>
                                </div>
                            </div>
                        )}
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Ignored</span>
                            <div className="flex items-center gap-2">
                                <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                                <span className="font-medium">{scan.ignored_count || 0}</span>
                            </div>
                        </div>
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Started</span>
                            <div className="flex items-center gap-2">
                                <Calendar className="h-4 w-4" />
                                <span className="text-sm">{new Date(scan.created_at).toLocaleString()}</span>
                            </div>
                        </div>
                        {scan.completed_at && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Completed</span>
                                <div className="flex items-center gap-2">
                                    <CheckCircle className="h-4 w-4 text-green-500" />
                                    <span className="text-sm">{new Date(scan.completed_at).toLocaleString()}</span>
                                </div>
                            </div>
                        )}
                    </div>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Severity Distribution</CardTitle>
                </CardHeader>
                <CardContent className="h-[200px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={severityData}
                                cx="50%"
                                cy="50%"
                                innerRadius={60}
                                outerRadius={80}
                                paddingAngle={5}
                                dataKey="value"
                            >
                                {severityData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                </CardContent>
            </Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
            <TabsTrigger value="overview">All Findings</TabsTrigger>
            {showSecurity && <TabsTrigger value="security">Security</TabsTrigger>}
            {showSecrets && <TabsTrigger value="secrets">Secrets</TabsTrigger>}
            {showSast && <TabsTrigger value="sast">SAST</TabsTrigger>}
            {showCompliance && <TabsTrigger value="compliance">Compliance</TabsTrigger>}
            {showQuality && <TabsTrigger value="quality">Quality</TabsTrigger>}
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
            <FindingsTable scanId={scanId!} />
        </TabsContent>

        {showSecurity && (
            <TabsContent value="security" className="space-y-4">
                <FindingsTable scanId={scanId!} category="security" />
            </TabsContent>
        )}

        {showSecrets && (
            <TabsContent value="secrets" className="space-y-4">
                <FindingsTable scanId={scanId!} category="secret" />
            </TabsContent>
        )}

        {showSast && (
            <TabsContent value="sast" className="space-y-4">
                <FindingsTable scanId={scanId!} category="sast" />
            </TabsContent>
        )}

        {showCompliance && (
            <TabsContent value="compliance" className="space-y-4">
                <FindingsTable scanId={scanId!} category="compliance" />
            </TabsContent>
        )}

        {showQuality && (
            <TabsContent value="quality" className="space-y-4">
                <FindingsTable scanId={scanId!} category="quality" />
            </TabsContent>
        )}
      </Tabs>
    </div>
  )
}
