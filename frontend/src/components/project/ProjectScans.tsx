import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getProjectScans, getProjectBranches } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ChevronLeft, ChevronRight, GitBranch, GitCommit, Calendar, ShieldAlert, Activity, X, ExternalLink } from 'lucide-react'

interface ProjectScansProps {
  projectId: string
}

export function ProjectScans({ projectId }: ProjectScansProps) {
  const [page, setPage] = useState(0)
  const [selectedBranch, setSelectedBranch] = useState<string | undefined>(undefined)
  const limit = 20
  const navigate = useNavigate()

  const { data: branches } = useQuery({
    queryKey: ['project-branches', projectId],
    queryFn: () => getProjectBranches(projectId),
  })

  const { data: scans, isLoading, isPlaceholderData } = useQuery({
    queryKey: ['project-scans', projectId, page, selectedBranch],
    queryFn: () => getProjectScans(projectId, page * limit, limit, selectedBranch),
    placeholderData: (previousData) => previousData,
  })

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    )
  }

  const scanList = scans || []
  const hasMore = scanList.length === limit

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Pipeline History</CardTitle>
            <CardDescription>View past pipelines and their security results.</CardDescription>
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
                <TableHead>Date</TableHead>
                <TableHead>Pipeline</TableHead>
                <TableHead>Branch</TableHead>
                <TableHead>Commit</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scanList.map((scan) => (
                <TableRow 
                  key={scan._id} 
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => navigate(`/projects/${projectId}/scans/${scan._id}`)}
                >
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      {new Date(scan.created_at).toLocaleString()}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs">
                        {scan.pipeline_iid ? `#${scan.pipeline_iid}` : 'N/A'}
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
                      <span className="font-mono text-xs">{scan.branch}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <GitCommit className="h-4 w-4 text-muted-foreground" />
                      <span className="font-mono text-xs">{scan.commit_hash?.substring(0, 7) || 'N/A'}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      {(scan.stats?.critical || 0) > 0 && (
                        <Badge variant="destructive" className="gap-1">
                          <ShieldAlert className="h-3 w-3" />
                          {scan.stats?.critical}
                        </Badge>
                      )}
                      {(scan.stats?.high || 0) > 0 && (
                        <Badge variant="secondary" className="gap-1 text-orange-500 border-orange-500/20 bg-orange-500/10">
                          <Activity className="h-3 w-3" />
                          {scan.stats?.high}
                        </Badge>
                      )}
                      {!(scan.stats?.critical || 0) && !(scan.stats?.high || 0) && (
                        <span className="text-muted-foreground text-sm">No high risks</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={scan.status === 'completed' ? 'default' : 'secondary'}>
                      {scan.status}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
              {scanList.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
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
