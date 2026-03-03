import { useState } from 'react'
import { projectApi } from '@/api/projects'
import { useProjectArchives, useRestoreArchive } from '@/hooks/queries/use-projects'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ChevronLeft, ChevronRight, Archive, RotateCcw, Download, GitBranch, GitCommit } from 'lucide-react'
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
  const size = 20

  const { data, isLoading } = useProjectArchives(projectId, page, size)
  const restoreMutation = useRestoreArchive()

  const handleRestore = () => {
    if (!restoreScanId) return
    restoreMutation.mutate(
      { projectId, scanId: restoreScanId },
      {
        onSuccess: (result) => {
          toast.success("Archive restored", {
            description: result.message,
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

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Archives</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
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
          {archives.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Archive className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No archived scans found.</p>
              <p className="text-sm mt-1">
                Scans will appear here when data retention archiving is enabled.
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
                    <TableHead>Archived At</TableHead>
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
                      <TableCell className="text-sm">
                        {formatDateTime(archive.archived_at)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {formatBytes(archive.compressed_size_bytes)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            title="Download archive"
                            onClick={() => handleDownload(archive.scan_id)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            title="Restore to database"
                            onClick={() => setRestoreScanId(archive.scan_id)}
                          >
                            <RotateCcw className="h-4 w-4" />
                          </Button>
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
              This will restore the archived scan data back into the database and remove it from S3 storage. The scan and all related data (findings, dependencies, analysis results) will be available again.
            </DialogDescription>
          </DialogHeader>
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
