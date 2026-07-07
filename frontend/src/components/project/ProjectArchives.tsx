import { useState, useMemo } from 'react'
import { projectApi } from '@/api/projects'
import { useProjectArchives, useRestoreArchive, useArchiveBranches } from '@/hooks/queries/use-projects'
import { useAuth } from '@/context/useAuth'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ChevronLeft, ChevronRight, Archive, RotateCcw, Download, GitBranch, GitCommit, AlertTriangle, Package, FileText } from 'lucide-react'
import { toast } from "sonner"
import { getErrorMessage, formatDateTime, shortCommitHash } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import type { ArchiveFilters } from '@/types/archive'

interface ProjectArchivesProps {
  projectId: string
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export function ProjectArchives({ projectId }: ProjectArchivesProps) {
  const [page, setPage] = useState(1)
  const [restoreScanId, setRestoreScanId] = useState<string | null>(null)
  const [branchFilter, setBranchFilter] = useState<string>('')
  const [dateFrom, setDateFrom] = useState<string>('')
  const [dateTo, setDateTo] = useState<string>('')
  const size = 20

  const { hasPermission } = useAuth()
  const canRestore = hasPermission('archive:restore')
  const canDownload = hasPermission('archive:download')

  const filters: ArchiveFilters | undefined = useMemo(() => {
    const f: ArchiveFilters = {}
    if (branchFilter) f.branch = branchFilter
    if (dateFrom) f.date_from = new Date(dateFrom).toISOString()
    if (dateTo) f.date_to = new Date(dateTo + 'T23:59:59').toISOString()
    return Object.keys(f).length > 0 ? f : undefined
  }, [branchFilter, dateFrom, dateTo])

  const { data, isLoading } = useProjectArchives(projectId, page, size, filters)
  const { data: branches } = useArchiveBranches(projectId)
  const restoreMutation = useRestoreArchive()

  const handleRestore = () => {
    if (!restoreScanId) return
    restoreMutation.mutate(
      { projectId, scanId: restoreScanId },
      {
        onSuccess: (result) => {
          toast.success("Archive restored", {
            description: `${result.message} The scan is now pinned and protected from housekeeping.`,
          })
          setRestoreScanId(null)
        },
        onError: (error) => {
          toast.error("Restore failed", {
            description: getErrorMessage(error),
          })
        },
      }
    )
  }

  const handleDownload = async (scanId: string) => {
    try {
      const blob = await projectApi.downloadArchive(projectId, scanId)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `archive-${scanId}.json.gz`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      a.remove()
    } catch (error) {
      toast.error("Download failed", {
        description: getErrorMessage(error),
      })
    }
  }

  const clearFilters = () => {
    setBranchFilter('')
    setDateFrom('')
    setDateTo('')
    setPage(1)
  }

  const hasActiveFilters = branchFilter || dateFrom || dateTo

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Archives</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {['s1', 's2', 's3'].map((skeletonId) => (
              <Skeleton key={skeletonId} className="h-12 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  const archives = data?.items || []
  const totalPages = data?.pages || 1

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Archive className="h-5 w-5" />
                Archives
              </CardTitle>
              <CardDescription>
                Archived scan data stored in S3. You can restore or download archived scans.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-end gap-3 mb-4">
            <div className="w-48">
              <label htmlFor="archive-branch-filter" className="text-xs font-medium text-muted-foreground mb-1 block">Branch</label>
              <Select value={branchFilter} onValueChange={(v) => { setBranchFilter(v === '_all' ? '' : v); setPage(1) }}>
                <SelectTrigger id="archive-branch-filter">
                  <SelectValue placeholder="All branches" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_all">All branches</SelectItem>
                  {(branches || []).map((b) => (
                    <SelectItem key={b} value={b}>{b}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label htmlFor="archive-date-from" className="text-xs font-medium text-muted-foreground mb-1 block">From</label>
              <Input
                id="archive-date-from"
                type="date"
                value={dateFrom}
                onChange={(e) => { setDateFrom(e.target.value); setPage(1) }}
                className="w-40"
              />
            </div>
            <div>
              <label htmlFor="archive-date-to" className="text-xs font-medium text-muted-foreground mb-1 block">To</label>
              <Input
                id="archive-date-to"
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

          {archives.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Archive className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No archived scans found.</p>
              <p className="text-sm mt-1">
                {hasActiveFilters
                  ? 'Try adjusting your filters.'
                  : 'Scans will appear here when data retention archiving is enabled.'}
              </p>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Branch</TableHead>
                    <TableHead>Commit</TableHead>
                    <TableHead>Scan Date</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead>Deps</TableHead>
                    <TableHead>SBOMs</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {archives.map((archive) => (
                    <TableRow key={archive.id}>
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
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          {canDownload && (
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Download archive"
                              onClick={() => handleDownload(archive.scan_id)}
                            >
                              <Download className="h-4 w-4" />
                            </Button>
                          )}
                          {canRestore && (
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Restore to database (pinned)"
                              onClick={() => setRestoreScanId(archive.scan_id)}
                            >
                              <RotateCcw className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {totalPages > 1 && (
                <div className="flex items-center justify-between pt-4">
                  <p className="text-sm text-muted-foreground">
                    Page {page} of {totalPages} ({data?.total} total)
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
                      onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                      disabled={page >= totalPages}
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

      <Dialog open={!!restoreScanId} onOpenChange={(open) => !open && setRestoreScanId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restore Archive</DialogTitle>
            <DialogDescription>
              This will restore the archived scan data back into the database and remove it from S3 storage.
              The restored scan will be <strong>pinned</strong> to prevent housekeeping from re-archiving it.
              You can unpin it later to allow normal retention processing.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-start gap-2 p-3 bg-amber-50 dark:bg-amber-950 rounded-md text-sm text-amber-800 dark:text-amber-200">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>The scan and all related data (findings, dependencies, analysis results) will be available again.</span>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRestoreScanId(null)}>Cancel</Button>
            <Button
              onClick={handleRestore}
              disabled={restoreMutation.isPending}
            >
              {restoreMutation.isPending ? "Restoring..." : "Restore"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
