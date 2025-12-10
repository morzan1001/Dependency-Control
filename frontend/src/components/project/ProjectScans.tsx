import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { getProjectScans } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ChevronLeft, ChevronRight, GitBranch, GitCommit, Calendar, ShieldAlert, Activity } from 'lucide-react'

interface ProjectScansProps {
  projectId: string
}

export function ProjectScans({ projectId }: ProjectScansProps) {
  const [page, setPage] = useState(0)
  const limit = 20

  const { data: scans, isLoading, isPlaceholderData } = useQuery({
    queryKey: ['project-scans', projectId, page],
    queryFn: () => getProjectScans(projectId, page * limit, limit),
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
        <CardTitle>Scan History</CardTitle>
        <CardDescription>View past security scans and their results.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Branch</TableHead>
                <TableHead>Commit</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scanList.map((scan) => (
                <TableRow key={scan._id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      {new Date(scan.created_at).toLocaleString()}
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
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" asChild>
                      <Link to={`/projects/${projectId}/scans/${scan._id}`}>
                        View Details
                      </Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {scanList.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No scans found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        
        <div className="flex items-center justify-end space-x-2 py-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(old => Math.max(old - 1, 0))}
            disabled={page === 0}
          >
            <ChevronLeft className="h-4 w-4" />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(old => old + 1)}
            disabled={!hasMore || isPlaceholderData}
          >
            Next
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
