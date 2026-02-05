import { useParams, Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useEffect, useRef, useCallback } from 'react'
import { SbomResponse, SbomTool, SbomToolComponent } from '@/api/scans'
import { useScan, useScanHistory, useTriggerRescan, useScanResults, useScanStats, useScanSboms } from '@/hooks/queries/use-scans'
import { useProject } from '@/hooks/queries/use-projects'
import { FindingsTable } from '@/components/findings/FindingsTable'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { ArrowLeft, GitBranch, GitCommit, ShieldAlert, Calendar, CheckCircle, FileJson, ExternalLink, PlayCircle, RefreshCw, Loader2, Tag, Folder } from 'lucide-react'
import { buildBranchUrl, buildCommitUrl, buildPipelineUrl } from '@/lib/scm-links'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { CodeBlock } from '@/components/ui/code-block'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { toast } from "sonner"
// PostProcessorResultCard removed - now showing raw JSON in Raw Data tab
import { isPostProcessorResult } from '@/lib/post-processors'
import { logger } from '@/lib/logger'
import { formatDateTime, shortCommitHash } from '@/lib/utils'
import { ScanContext } from '@/components/findings/details/SastDetailsView'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

interface ScanHistoryItem {
  id: string;
  is_rescan?: boolean;
  created_at: string;
}

export default function ScanDetails() {
  const { projectId, scanId } = useParams<{ projectId: string, scanId: string }>()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const sbomRefs = useRef<(HTMLDivElement | null)[]>([])
  const { data: scan, isLoading: isScanLoading } = useScan(scanId!)
  const { data: scanHistory } = useScanHistory(projectId!, scanId!)

  const activeTab = searchParams.get('tab') || 'overview';
  const sbomParam = searchParams.get('sbom');
  
  const handleTabChange = (val: string) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      next.set('tab', val);
      return next;
    }, { replace: true });
  };

  const { data: project, isLoading: isProjectLoading } = useProject(projectId!)
  const { data: scanResults, isLoading: isResultsLoading } = useScanResults(scanId!)
  const { data: scanSboms, isLoading: isSbomsLoading } = useScanSboms(scanId!)
  const { data: categoryStats } = useScanStats(scanId!)
  
  const triggerRescanMutation = useTriggerRescan()

  const scrollToSbom = useCallback((index: number) => {
    const sbomElement = sbomRefs.current[index]
    if (sbomElement) {
      sbomElement.scrollIntoView({ behavior: 'smooth', block: 'start' })
      sbomElement.classList.add('ring-2', 'ring-primary', 'ring-offset-2')
      setTimeout(() => {
        sbomElement.classList.remove('ring-2', 'ring-primary', 'ring-offset-2')
      }, 2000)
    }
  }, [])

  useEffect(() => {
    if (activeTab === 'raw' && sbomParam !== null && !isSbomsLoading && scanSboms && scanSboms.length > 0) {
      const sbomIndex = parseInt(sbomParam, 10)
      if (!isNaN(sbomIndex) && sbomIndex >= 0 && sbomIndex < scanSboms.length) {
        const timeoutId = setTimeout(() => scrollToSbom(sbomIndex), 100)
        return () => clearTimeout(timeoutId)
      }
    }
  }, [activeTab, sbomParam, isSbomsLoading, scanSboms, scrollToSbom])

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

  const scanContext: ScanContext = {
    projectUrl: scan.project_url || scan.metadata?.CI_PROJECT_URL,
    pipelineUrl: scan.pipeline_url,
    commitHash: scan.commit_hash,
    branch: scan.branch || scan.metadata?.CI_COMMIT_BRANCH,
  }

  const activeAnalyzers = project.active_analyzers || [];
  const showSecurity = activeAnalyzers.some(a => ['trivy', 'grype', 'osv', 'os_malware', 'typosquatting', 'deps_dev', 'hash_verification'].includes(a));
  const showSecrets = activeAnalyzers.includes('trufflehog');
  const showSast = activeAnalyzers.some(a => ['opengrep', 'kics', 'bearer'].includes(a));
  const showCompliance = activeAnalyzers.some(a => ['trivy', 'license_compliance', 'end_of_life'].includes(a));
  const showQuality = activeAnalyzers.some(a => ['outdated_packages', 'maintainer_risk'].includes(a));

  const stats = scan.stats || { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  
  const severityData = [
      { name: 'Critical', value: stats.critical || 0, color: '#ef4444' },
      { name: 'High', value: stats.high || 0, color: '#f97316' },
      { name: 'Medium', value: stats.medium || 0, color: '#eab308' },
      { name: 'Low', value: stats.low || 0, color: '#3b82f6' },
      { name: 'Info', value: stats.info || 0, color: '#60a5fa' },
      { name: 'Unknown', value: stats.unknown || 0, color: '#9ca3af' },
  ].filter(d => d.value > 0);

  const categoryData = categoryStats ? [
      { name: 'Security', value: categoryStats.security ?? 0, color: '#ef4444' },
      { name: 'Secrets', value: categoryStats.secret ?? 0, color: '#f97316' },
      { name: 'SAST', value: categoryStats.sast ?? 0, color: '#8b5cf6' },
      { name: 'Compliance', value: categoryStats.compliance ?? 0, color: '#3b82f6' },
      { name: 'Quality', value: categoryStats.quality ?? 0, color: '#10b981' },
      { name: 'Other', value: categoryStats.other ?? 0, color: '#9ca3af' },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
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
            <div className="flex items-center gap-2 mt-1">
                <p className="text-muted-foreground text-sm">ID: {scanId}</p>
            </div>
            </div>
        </div>
        <div className="flex items-center gap-2">
            {scanHistory && scanHistory.length > 1 && (
                <Select 
                    value={scanId} 
                    onValueChange={(value) => navigate(`/projects/${projectId}/scans/${value}`)}
                >
                    <SelectTrigger className="w-[250px]">
                        <SelectValue placeholder="Select version" />
                    </SelectTrigger>
                    <SelectContent>
                        {scanHistory.map((h: ScanHistoryItem) => (
                            <SelectItem key={h.id} value={h.id}>
                                {h.is_rescan ? 'Re-scan' : 'Original'} - {formatDateTime(h.created_at)}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
            )}
            <Button 
                onClick={() => triggerRescanMutation.mutate({ projectId: projectId!, scanId: scanId! }, {
                     onSuccess: () => {
                         toast.success("Re-scan triggered", {
                            description: "A new scan has been started.",
                          })
                     },
                     onError: () => {
                          toast.error("Error", {
                            description: "Failed to trigger re-scan.",
                          })
                     }
                })} 
                disabled={triggerRescanMutation.isPending || !scan.sbom_refs || scan.sbom_refs.length === 0}
            >
                <RefreshCw className={`mr-2 h-4 w-4 ${triggerRescanMutation.isPending ? 'animate-spin' : ''}`} />
                Trigger Re-scan
            </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
          <Card>
                <CardHeader>
                    <CardTitle>Scan Metadata</CardTitle>
                </CardHeader>
                <CardContent className="h-[300px] overflow-y-auto pr-2">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Status</span>
                            <div>
                                <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'} className="flex w-fit items-center gap-1">
                                    {['pending', 'processing'].includes(scan.status) && <Loader2 className="h-3 w-3 animate-spin" />}
                                    {scan.status}
                                </Badge>
                            </div>
                        </div>
                        <div className="flex flex-col space-y-1">
                            <span className="text-sm text-muted-foreground">Branch</span>
                            <div className="flex items-center gap-2">
                                <GitBranch className="h-4 w-4" />
                                                                {(() => {
                                                                    const projectUrl = scan.project_url || scan.metadata?.CI_PROJECT_URL
                                                                    const href = buildBranchUrl({
                                                                        projectUrl,
                                                                        pipelineUrl: scan.pipeline_url,
                                                                        branch: scan.branch,
                                                                    })

                                                                    return href ? (
                                                                        <a
                                                                            href={href}
                                                                            target="_blank"
                                                                            rel="noopener noreferrer"
                                                                            className="flex items-center gap-2 text-primary hover:underline"
                                                                        >
                                                                            <span className="font-medium">{scan.branch}</span>
                                                                            <ExternalLink className="h-3 w-3" />
                                                                        </a>
                                                                    ) : (
                                                                        <span className="font-medium">{scan.branch}</span>
                                                                    )
                                                                })()}
                            </div>
                        </div>
                        {scan.commit_hash && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Commit</span>
                                <div className="flex items-center gap-2">
                                    <GitCommit className="h-4 w-4" />
                                                                        {(() => {
                                                                            const projectUrl = scan.project_url || scan.metadata?.CI_PROJECT_URL
                                                                            const href = buildCommitUrl({
                                                                                projectUrl,
                                                                                pipelineUrl: scan.pipeline_url,
                                                                                commitHash: scan.commit_hash,
                                                                            })

                                                                            return href ? (
                                                                                <a
                                                                                    href={href}
                                                                                    target="_blank"
                                                                                    rel="noopener noreferrer"
                                                                                    className="flex items-center gap-2 text-primary hover:underline"
                                                                                >
                                                                                    <span className="font-medium font-mono text-xs">{shortCommitHash(scan.commit_hash)}</span>
                                                                                    <ExternalLink className="h-3 w-3" />
                                                                                </a>
                                                                            ) : (
                                                                                <span className="font-medium font-mono text-xs">{shortCommitHash(scan.commit_hash)}</span>
                                                                            )
                                                                        })()}
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
                            <span className="text-sm text-muted-foreground">Scan Started</span>
                            <div className="flex items-center gap-2">
                                <Calendar className="h-4 w-4" />
                                <span className="text-sm">{formatDateTime(scan.created_at)}</span>
                            </div>
                        </div>
                        {scan.completed_at && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Scan Completed</span>
                                <div className="flex items-center gap-2">
                                    <CheckCircle className="h-4 w-4 text-success" />
                                    <span className="text-sm">{formatDateTime(scan.completed_at)}</span>
                                </div>
                            </div>
                        )}
                        {scan.job_started_at && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Pipeline Started</span>
                                <div className="flex items-center gap-2">
                                    <PlayCircle className="h-4 w-4 text-blue-500" />
                                    <span className="text-sm">{formatDateTime(scan.job_started_at)}</span>
                                </div>
                            </div>
                        )}
                                                {(() => {
                                                    const projectUrl = scan.project_url || scan.metadata?.CI_PROJECT_URL
                                                    const pipelineId = scan.pipeline_id ?? scan.metadata?.CI_PIPELINE_ID
                                                    const href = buildPipelineUrl({
                                                        projectUrl,
                                                        pipelineUrl: scan.pipeline_url,
                                                        pipelineId,
                                                    })

                                                    if (!href || !pipelineId) return null

                                                    return (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Pipeline</span>
                                <a 
                                                                        href={href}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-2 text-primary hover:underline"
                                >
                                    <PlayCircle className="h-4 w-4" />
                                                                        <span className="font-medium">#{pipelineId}</span>
                                    <ExternalLink className="h-3 w-3" />
                                </a>
                            </div>
                                                    )
                                                })()}
                        {scan.metadata?.CI_JOB_ID && scan.metadata?.CI_PROJECT_URL && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Job</span>
                                <a 
                                    href={`${scan.metadata.CI_PROJECT_URL}/-/jobs/${scan.metadata.CI_JOB_ID}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-2 text-primary hover:underline"
                                >
                                    <FileJson className="h-4 w-4" />
                                    <span className="font-medium">#{scan.metadata.CI_JOB_ID}</span>
                                    <ExternalLink className="h-3 w-3" />
                                </a>
                            </div>
                        )}
                        {scan.metadata?.CI_COMMIT_TAG && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Tag</span>
                                <div className="flex items-center gap-2">
                                    <Tag className="h-4 w-4 text-amber-500" />
                                    <span className="font-medium">{scan.metadata.CI_COMMIT_TAG}</span>
                                </div>
                            </div>
                        )}
                        {scan.metadata?.CI_PROJECT_PATH && (
                            <div className="flex flex-col space-y-1">
                                <span className="text-sm text-muted-foreground">Project Path</span>
                                {scan.metadata?.CI_PROJECT_URL ? (
                                    <a 
                                        href={scan.metadata.CI_PROJECT_URL}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-2 text-primary hover:underline"
                                    >
                                        <Folder className="h-4 w-4" />
                                        <span className="font-medium text-sm">{scan.metadata.CI_PROJECT_PATH}</span>
                                        <ExternalLink className="h-3 w-3" />
                                    </a>
                                ) : (
                                    <div className="flex items-center gap-2">
                                        <Folder className="h-4 w-4" />
                                        <span className="font-medium text-sm">{scan.metadata.CI_PROJECT_PATH}</span>
                                    </div>
                                )}
                            </div>
                        )}
                        {scan.metadata?.CI_COMMIT_MESSAGE && (
                            <div className="col-span-2 flex flex-col space-y-1 border-t pt-2 mt-2">
                                <span className="text-sm text-muted-foreground">Commit Message</span>
                                <span className="text-sm font-medium truncate" title={scan.metadata.CI_COMMIT_MESSAGE}>
                                    {scan.metadata.CI_COMMIT_MESSAGE}
                                </span>
                            </div>
                        )}
                    </div>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Severity Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="h-[300px] w-full min-w-0">
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
                                <Legend verticalAlign="bottom" height={36}/>
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle>Category Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="h-[300px] w-full min-w-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={categoryData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {categoryData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip />
                                <Legend verticalAlign="bottom" height={36}/>
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </CardContent>
            </Card>
      </div>

            <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-4">
        <TabsList>
            <TabsTrigger value="overview">All Findings</TabsTrigger>
            {showSecurity && <TabsTrigger value="security">Security</TabsTrigger>}
            {showSecrets && <TabsTrigger value="secrets">Secrets</TabsTrigger>}
            {showSast && <TabsTrigger value="sast">SAST</TabsTrigger>}
            {showCompliance && <TabsTrigger value="compliance">Compliance</TabsTrigger>}
            {showQuality && <TabsTrigger value="quality">Quality</TabsTrigger>}

            <TabsTrigger value="raw">Raw Data</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
            <FindingsTable scanId={scanId!} projectId={projectId!} scanContext={scanContext} />
        </TabsContent>

        {showSecurity && (
            <TabsContent value="security" className="space-y-4">
                <FindingsTable scanId={scanId!} projectId={projectId!} category="security" scanContext={scanContext} />
            </TabsContent>
        )}

        {showSecrets && (
            <TabsContent value="secrets" className="space-y-4">
                <FindingsTable scanId={scanId!} projectId={projectId!} category="secret" scanContext={scanContext} />
            </TabsContent>
        )}

        {showSast && (
            <TabsContent value="sast" className="space-y-4">
                <FindingsTable scanId={scanId!} projectId={projectId!} category="sast" scanContext={scanContext} />
            </TabsContent>
        )}

        {showCompliance && (
            <TabsContent value="compliance" className="space-y-4">
                <FindingsTable scanId={scanId!} projectId={projectId!} category="compliance" scanContext={scanContext} />
            </TabsContent>
        )}

        {showQuality && (
            <TabsContent value="quality" className="space-y-4">
                <FindingsTable scanId={scanId!} projectId={projectId!} category="quality" scanContext={scanContext} />
            </TabsContent>
        )}

        <TabsContent value="raw" className="space-y-4">
            {isResultsLoading ? (
                <div className="grid gap-4 md:grid-cols-1">
                    <Skeleton className="h-[400px]" />
                    <Skeleton className="h-[400px]" />
                </div>
            ) : (
                <div className="space-y-8">
                    {/* Post-Processor Results (EPSS/KEV, Reachability) - RAW JSON */}
                    {scanResults && scanResults.filter(r => isPostProcessorResult(r.analyzer_name)).length > 0 && (
                        <div className="space-y-4">
                            <h3 className="text-lg font-medium">Post-Processor Results (Raw JSON)</h3>
                            <div className="grid gap-6">
                                {scanResults
                                    .filter(r => isPostProcessorResult(r.analyzer_name))
                                    .map((result) => (
                                        <Card key={result.id} className="overflow-hidden">
                                            <CardHeader className="bg-muted/50 pb-4">
                                                <CardTitle className="text-lg flex items-center justify-between">
                                                    <span className="capitalize">{result.analyzer_name}</span>
                                                    <Badge variant="outline">Post-Processor</Badge>
                                                </CardTitle>
                                            </CardHeader>
                                            <CardContent className="p-0">
                                                <CodeBlock code={JSON.stringify(result.result, null, 2)} />
                                            </CardContent>
                                        </Card>
                                    ))}
                            </div>
                        </div>
                    )}

                    {/* Analysis Results (non-post-processor) */}
                    {scanResults && scanResults.filter(r => !isPostProcessorResult(r.analyzer_name)).length > 0 && (
                        <div className="space-y-4">
                            <h3 className="text-lg font-medium">Scanner Results</h3>
                            <div className="grid gap-6">
                                {scanResults
                                    .filter(r => !isPostProcessorResult(r.analyzer_name))
                                    .map((result) => (
                                    <Card key={result.id} className="overflow-hidden">
                                        <CardHeader className="bg-muted/50 pb-4">
                                            <CardTitle className="text-lg flex items-center justify-between">
                                                <span className="capitalize">{result.analyzer_name}</span>
                                                <Badge variant="outline">Result</Badge>
                                            </CardTitle>
                                        </CardHeader>
                                        <CardContent className="p-0">
                                            <CodeBlock code={JSON.stringify(result.result, null, 2)} />
                                        </CardContent>
                                    </Card>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Raw SBOMs */}
                    <div className="space-y-4">
                        <h3 className="text-lg font-medium flex items-center gap-2">
                            <FileJson className="h-5 w-5" />
                            Raw SBOMs
                            {isSbomsLoading && <Loader2 className="h-4 w-4 animate-spin" />}
                        </h3>
                        {isSbomsLoading ? (
                            <div className="grid gap-6">
                                <Skeleton className="h-[400px]" />
                            </div>
                        ) : scanSboms && scanSboms.length > 0 ? (
                            <div className="grid gap-6">
                                {scanSboms.map((sbomResponse: SbomResponse) => {
                                    const sbom = sbomResponse.sbom;
                                    const index = sbomResponse.index;
                                    let toolName = "";
                                    let sbomName = sbomResponse.filename || `SBOM #${index + 1}`;
                                    
                                    if (sbomResponse.error) {
                                        return (
                                            <Card 
                                                key={index} 
                                                ref={(el) => { sbomRefs.current[index] = el }}
                                                className="transition-all duration-300 border-destructive"
                                            >
                                                <CardHeader className="bg-destructive/10 pb-4">
                                                    <CardTitle className="text-lg flex items-center justify-between">
                                                        <span>{sbomName}</span>
                                                        <Badge variant="destructive">Load Error</Badge>
                                                    </CardTitle>
                                                </CardHeader>
                                                <CardContent className="p-4">
                                                    <p className="text-destructive">{sbomResponse.error}</p>
                                                </CardContent>
                                            </Card>
                                        );
                                    }
                                    
                                    if (!sbom) return null;
                                    
                                    try {
                                        if (sbom.metadata?.component?.name) {
                                            sbomName = sbom.metadata.component.name;
                                        } else if (sbom.serialNumber) {
                                            sbomName = sbom.serialNumber;
                                        }

                                        if (sbom.metadata?.tools) {
                                            if (Array.isArray(sbom.metadata.tools)) {
                                                toolName = sbom.metadata.tools.map((t: SbomTool) => t.name || t.vendor).join(', ');
                                            } else if (sbom.metadata.tools.components) {
                                                toolName = sbom.metadata.tools.components.map((c: SbomToolComponent) => c.name).join(', ');
                                            }
                                        }
                                    } catch (e) {
                                        logger.warn("Failed to extract tool name", e);
                                    }

                                    return (
                                        <Card 
                                            key={index} 
                                            ref={(el) => { sbomRefs.current[index] = el }}
                                            className="transition-all duration-300"
                                        >
                                            <CardHeader className="bg-muted/50 pb-4">
                                                <CardTitle className="text-lg flex items-center justify-between">
                                                    <span>{sbomName}</span>
                                                    <div className="flex items-center gap-2">
                                                        <Badge variant="secondary" className="font-mono">SBOM #{index + 1}</Badge>
                                                        {toolName && (
                                                            <Badge variant="outline">{toolName}</Badge>
                                                        )}
                                                        {sbomResponse.storage === 'gridfs' && (
                                                            <Badge variant="outline" className="text-xs">GridFS</Badge>
                                                        )}
                                                    </div>
                                                </CardTitle>
                                            </CardHeader>
                                            <CardContent className="p-0">
                                                <CodeBlock code={JSON.stringify(sbom, null, 2)} />
                                            </CardContent>
                                        </Card>
                                    )
                                })}
                            </div>
                        ) : scan.sbom_refs && scan.sbom_refs.length > 0 ? (
                            <Card>
                                <CardHeader className="bg-muted/50">
                                    <CardTitle className="text-lg">SBOM References</CardTitle>
                                </CardHeader>
                                <CardContent className="p-4">
                                    <p className="text-muted-foreground mb-4">
                                        {scan.sbom_refs.length} SBOM(s) stored in GridFS. Loading...
                                    </p>
                                    <CodeBlock code={JSON.stringify(scan.sbom_refs, null, 2)} />
                                </CardContent>
                            </Card>
                        ) : (
                            <Card>
                                <CardHeader>
                                    <CardTitle>No SBOMs Available</CardTitle>
                                </CardHeader>
                                <CardContent className="p-4">
                                    <p className="text-muted-foreground">No SBOM data found for this scan.</p>
                                </CardContent>
                            </Card>
                        )}
                    </div>
                </div>
            )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
