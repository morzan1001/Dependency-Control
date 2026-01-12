import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '@/api/scans'
import { projectApi } from '@/api/projects'
import { Scan } from '@/types/scan'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ChevronLeft, ChevronRight, GitBranch, GitCommit, Calendar, ShieldAlert, Activity, X, ExternalLink, ArrowUp, ArrowDown, RefreshCw, Loader2 } from 'lucide-react'
import { buildBranchUrl, buildCommitUrl, buildPipelineUrl } from '@/lib/scm-links'

interface ProjectScansProps {
  projectId: string
}

// Helper to get the effective stats and status (from latest re-scan if available)
const getEffectiveScanData = (scan: Scan) => {
    const source = scan.latest_run || scan;
    return {
        stats: source.stats || { critical: 0, high: 0, medium: 0, low: 0 },
        status: source.status,
        date: source.completed_at || source.created_at || scan.created_at
    };
};

export function ProjectScans({ projectId }: ProjectScansProps) {
  const [page, setPage] = useState(0)
  const [selectedBranch, setSelectedBranch] = useState<string | undefined>(undefined)
  const [sortBy, setSortBy] = useState("created_at")
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc")
  const limit = 20
  const navigate = useNavigate()

  const { data: branches } = useQuery({
    queryKey: ['project-branches', projectId],
    queryFn: () => projectApi.getBranches(projectId),
  })

  const { data: scans, isLoading, isPlaceholderData } = useQuery({
    queryKey: ['project-scans', projectId, page, selectedBranch, sortBy, sortOrder],
    queryFn: () => scanApi.getProjectScans(projectId, page * limit, limit, selectedBranch, sortBy, sortOrder, true),
    placeholderData: (previousData) => previousData,
  })

  const renderSortIcon = (column: string) => {
    if (sortBy === column) {
      return sortOrder === 'asc' ? <ArrowUp className="ml-2 h-4 w-4 inline" /> : <ArrowDown className="ml-2 h-4 w-4 inline" />;
    }
    return null;
  };

  const handleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
  };

  const scanList = scans || []
  const hasMore = scanList.length === limit

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Pipelines</CardTitle>
            <CardDescription>View past pipelines and their latest security status.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {selectedBranch && (
              <Button 
                variant="ghost" 
                size="icon" 
                onClick={() => {
                  setSelectedBranch(undefined)
                  setPage(0)
                }}
              >
                <X className="h-4 w-4" />
              </Button>
            )}
            <Select 
              value={selectedBranch || "all"} 
              onValueChange={(value) => {
                setSelectedBranch(value === "all" ? undefined : value)
                setPage(0)
              }}
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by branch" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Branches</SelectItem>
                {branches?.map((branch) => (
                  <SelectItem key={branch} value={branch}>
                    {branch}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[200px] cursor-pointer hover:text-foreground" onClick={() => handleSort('created_at')}>
                  Date {renderSortIcon('created_at')}
                </TableHead>
                <TableHead className="w-[120px] cursor-pointer hover:text-foreground" onClick={() => handleSort('pipeline_iid')}>
                  Source {renderSortIcon('pipeline_iid')}
                </TableHead>
                <TableHead className="w-[200px] cursor-pointer hover:text-foreground" onClick={() => handleSort('branch')}>
                  Branch {renderSortIcon('branch')}
                </TableHead>
                <TableHead className="w-[120px]">Commit</TableHead>
                <TableHead className="w-[250px] cursor-pointer hover:text-foreground" onClick={() => handleSort('findings_count')}>
                  Findings {renderSortIcon('findings_count')}
                </TableHead>
                <TableHead className="w-[120px] cursor-pointer hover:text-foreground" onClick={() => handleSort('status')}>
                  Status {renderSortIcon('status')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i}>
                      <TableCell><Skeleton className="h-6 w-32" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-24" /></TableCell>
                      <TableCell><Skeleton className="h-6 w-20" /></TableCell>
                  </TableRow>
              ))}
              {!isLoading && scanList.map((scan) => (
                <TableRow 
                  key={scan._id} 
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => navigate(`/projects/${projectId}/scans/${scan.latest_rescan_id || scan._id}`)}
                >
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      {(() => {
                          const { date } = getEffectiveScanData(scan);
                          return new Date(date).toLocaleString();
                      })()}
                    </div>
                    {scan.latest_rescan_id && (
                        <div className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                            <RefreshCw className="h-3 w-3" />
                            Updated via re-scan
                        </div>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs">
                        {(() => {
                          const projectUrl = scan.project_url || scan.metadata?.CI_PROJECT_URL
                          const pipelineId = scan.pipeline_id
                          const href = buildPipelineUrl({
                            projectUrl,
                            pipelineUrl: scan.pipeline_url,
                            pipelineId,
                          })

                          if (!scan.pipeline_iid) return 'N/A'
                          if (!href) return `#${scan.pipeline_iid}`

                          return (
                            <a
                              href={href}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="text-primary hover:underline"
                            >
                              #{scan.pipeline_iid}
                            </a>
                          )
                        })()}
                      </span>
                      {scan.metadata?.CI_PROJECT_URL && (
                        <a 
                          href={scan.metadata.CI_PROJECT_URL}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="text-muted-foreground hover:text-primary"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <GitBranch className="h-4 w-4 text-muted-foreground" />
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
                            onClick={(e) => e.stopPropagation()}
                            className="font-mono text-xs text-primary hover:underline"
                          >
                            {scan.branch}
                          </a>
                        ) : (
                          <span className="font-mono text-xs">{scan.branch}</span>
                        )
                      })()}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <GitCommit className="h-4 w-4 text-muted-foreground" />
                      {(() => {
                        const shortSha = scan.commit_hash?.substring(0, 7)
                        if (!shortSha) return <span className="font-mono text-xs">N/A</span>

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
                            onClick={(e) => e.stopPropagation()}
                            className="font-mono text-xs text-primary hover:underline"
                            title={scan.commit_hash}
                          >
                            {shortSha}
                          </a>
                        ) : (
                          <span className="font-mono text-xs">{shortSha}</span>
                        )
                      })()}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      {(() => {
                          const { stats } = getEffectiveScanData(scan);
                          return (
                              <>
                                {(stats.critical || 0) > 0 && (
                                    <Badge variant="destructive" className="gap-1">
                                    <ShieldAlert className="h-3 w-3" />
                                    {stats.critical}
                                    </Badge>
                                )}
                                {(stats.high || 0) > 0 && (
                                    <Badge variant="secondary" className="gap-1 text-orange-500 border-orange-500/20 bg-orange-500/10">
                                    <Activity className="h-3 w-3" />
                                    {stats.high}
                                    </Badge>
                                )}
                                {!(stats.critical || 0) && !(stats.high || 0) && (
                                    <span className="text-muted-foreground text-sm">No high risks</span>
                                )}
                              </>
                          );
                      })()}
                    </div>
                  </TableCell>
                  <TableCell>
                    {(() => {
                        const { status } = getEffectiveScanData(scan);
                        return (
                            <Badge variant={status === 'completed' ? 'default' : 'secondary'} className="flex w-fit items-center gap-1">
                            {['pending', 'processing'].includes(status) && <Loader2 className="h-3 w-3 animate-spin" />}
                            {status}
                            </Badge>
                        );
                    })()}
                  </TableCell>
                </TableRow>
              ))}
              {!isLoading && scanList.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No scans found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        
        {!(page === 0 && !hasMore) && (
          <div className="flex items-center justify-end space-x-2 py-4">
            {page > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(old => Math.max(old - 1, 0))}
              >
                <ChevronLeft className="h-4 w-4" />
                Previous
              </Button>
            )}
            {hasMore && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(old => old + 1)}
                disabled={isPlaceholderData}
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
