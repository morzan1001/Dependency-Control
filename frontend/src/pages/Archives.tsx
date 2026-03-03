import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useAdminArchives } from '@/hooks/queries/use-archives'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ChevronLeft, ChevronRight, Archive, GitBranch, GitCommit, Package, FileText } from 'lucide-react'
import { formatDateTime, shortCommitHash } from '@/lib/utils'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { ArchiveFilters } from '@/types/archive'

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function ArchivesPage() {
  const [page, setPage] = useState(1)
  const [branchFilter, setBranchFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const size = 20

  const filters: (ArchiveFilters & { project_id?: string }) | undefined = useMemo(() => {
    const f: ArchiveFilters & { project_id?: string } = {}
    if (branchFilter) f.branch = branchFilter
    if (dateFrom) f.date_from = new Date(dateFrom).toISOString()
    if (dateTo) f.date_to = new Date(dateTo + 'T23:59:59').toISOString()
    return Object.keys(f).length > 0 ? f : undefined
  }, [branchFilter, dateFrom, dateTo])

  const { data, isLoading } = useAdminArchives(page, size, filters)

  const clearFilters = () => {
    setBranchFilter('')
    setDateFrom('')
    setDateTo('')
    setPage(1)
  }

  const hasActiveFilters = branchFilter || dateFrom || dateTo

  return (
    <div className="container mx-auto py-10 space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Archives</h1>
        <p className="text-muted-foreground">
          Overview of all archived scans across all projects.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Archive className="h-5 w-5" />
            All Archived Scans
          </CardTitle>
          <CardDescription>
            Browse archived scan data across all projects. Navigate to a project to restore or download archives.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Filters */}
          <div className="flex flex-wrap items-end gap-3 mb-4">
            <div>
              <label htmlFor="admin-branch-filter" className="text-xs font-medium text-muted-foreground mb-1 block">Branch</label>
              <Input
                id="admin-branch-filter"
                placeholder="Filter by branch..."
                value={branchFilter}
                onChange={(e) => { setBranchFilter(e.target.value); setPage(1) }}
                className="w-48"
              />
            </div>
            <div>
              <label htmlFor="admin-date-from" className="text-xs font-medium text-muted-foreground mb-1 block">From</label>
              <Input
                id="admin-date-from"
                type="date"
                value={dateFrom}
                onChange={(e) => { setDateFrom(e.target.value); setPage(1) }}
                className="w-40"
              />
            </div>
            <div>
              <label htmlFor="admin-date-to" className="text-xs font-medium text-muted-foreground mb-1 block">To</label>
              <Input
                id="admin-date-to"
                type="date"
                value={dateTo}
                onChange={(e) => { setDateTo(e.target.value); setPage(1) }}
                className="w-40"
              />
            </div>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            )}
          </div>

          {isLoading ? (
            <div className="space-y-2">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : (data?.items || []).length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Archive className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No archived scans found.</p>
              <p className="text-sm mt-1">
                {hasActiveFilters
                  ? 'Try adjusting your filters.'
                  : 'Archives will appear here when data retention archiving is active.'}
              </p>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Project</TableHead>
                    <TableHead>Branch</TableHead>
                    <TableHead>Commit</TableHead>
                    <TableHead>Scan Date</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead>Deps</TableHead>
                    <TableHead>SBOMs</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Archived At</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.items || []).map((archive) => (
                    <TableRow key={archive.id}>
                      <TableCell>
                        <Link
                          to={`/projects/${archive.project_id}`}
                          className="text-sm font-medium text-primary hover:underline"
                        >
                          {archive.project_name || archive.project_id}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <GitBranch className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="font-mono text-sm">{archive.branch || '-'}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <GitCommit className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="font-mono text-sm">
                            {archive.commit_hash ? shortCommitHash(archive.commit_hash) : '-'}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        {archive.scan_created_at ? formatDateTime(archive.scan_created_at) : '-'}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm">{archive.findings_count}</span>
                          {archive.critical_findings_count > 0 && (
                            <Badge variant="destructive" className="text-xs px-1.5 py-0">
                              {archive.critical_findings_count} C
                            </Badge>
                          )}
                          {archive.high_findings_count > 0 && (
                            <Badge variant="secondary" className="text-xs px-1.5 py-0 bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
                              {archive.high_findings_count} H
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        <div className="flex items-center gap-1">
                          <Package className="h-3.5 w-3.5 text-muted-foreground" />
                          {archive.dependencies_count}
                        </div>
                      </TableCell>
                      <TableCell>
                        {archive.sbom_filenames.length > 0 ? (
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div className="flex items-center gap-1 cursor-help">
                                  <FileText className="h-3.5 w-3.5 text-muted-foreground" />
                                  <span className="text-sm">{archive.sbom_filenames.length}</span>
                                </div>
                              </TooltipTrigger>
                              <TooltipContent>
                                <ul className="text-xs space-y-0.5">
                                  {archive.sbom_filenames.map((f) => (
                                    <li key={f} className="font-mono">{f}</li>
                                  ))}
                                </ul>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        ) : (
                          <span className="text-sm text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm">
                        {formatBytes(archive.compressed_size_bytes)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {formatDateTime(archive.archived_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {(data?.pages || 1) > 1 && (
                <div className="flex items-center justify-between pt-4">
                  <p className="text-sm text-muted-foreground">
                    Page {page} of {data?.pages} ({data?.total} total)
                  </p>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(p => Math.max(1, p - 1))}
                      disabled={page <= 1}
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(p => Math.min(data?.pages || 1, p + 1))}
                      disabled={page >= (data?.pages || 1)}
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
