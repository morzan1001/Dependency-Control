import { useState } from 'react'
import { Link } from 'react-router-dom'
import { archiveFilters, NO_ARCHIVE_FILTER, useAdminArchives, type ArchiveFilterValue } from '@/hooks/queries/use-archives'
import { useDebounce } from '@/hooks/use-debounce'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Pagination } from '@/components/ui/pagination'
import { Skeleton } from '@/components/ui/skeleton'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  ArchiveEmptyState,
  ArchiveFilterBar,
  ArchiveSummaryCells,
  ArchiveSummaryHead,
} from '@/components/project/ProjectArchives'
import { Archive } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'

const ARCHIVE_SKELETON_KEYS = ['s1', 's2', 's3', 's4', 's5']

export default function ArchivesPage() {
  const [page, setPage] = useState(1)
  const [filter, setFilter] = useState(NO_ARCHIVE_FILTER)
  const debouncedBranch = useDebounce(filter.branch)
  const size = 20

  const filters = archiveFilters({ ...filter, branch: debouncedBranch })
  const updateFilter = (patch: Partial<ArchiveFilterValue>) => {
    setFilter((current) => ({ ...current, ...patch }))
    setPage(1)
  }

  const { data, isLoading } = useAdminArchives(page, size, filters)

  const items = data?.items || []
  const totalPages = data?.pages || 1

  const renderContent = () => {
    if (isLoading) {
      return (
        <div className="space-y-2">
          {ARCHIVE_SKELETON_KEYS.map((skeletonId) => (
            <Skeleton key={skeletonId} className="h-12 w-full" />
          ))}
        </div>
      )
    }

    if (items.length === 0) {
      const filtered = filter.branch || filter.from || filter.to
      return (
        <ArchiveEmptyState
          hint={filtered ? 'Try adjusting your filters.' : 'Archives will appear here when data retention archiving is active.'}
        />
      )
    }

    return (
      <>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Project</TableHead>
              <ArchiveSummaryHead />
              <TableHead>Archived At</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((archive) => (
              <TableRow key={archive.id}>
                <TableCell>
                  <Link
                    to={`/projects/${archive.project_id}`}
                    className="text-sm font-medium text-primary hover:underline"
                  >
                    {archive.project_name || archive.project_id}
                  </Link>
                </TableCell>
                <ArchiveSummaryCells archive={archive} />
                <TableCell className="text-sm">
                  {formatDateTime(archive.archived_at)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>

        <Pagination page={page} totalPages={totalPages} total={data?.total} onChange={setPage} />
      </>
    )
  }

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
          <ArchiveFilterBar value={filter} onChange={updateFilter}>
            <div>
              <label htmlFor="admin-branch-filter" className="text-xs font-medium text-muted-foreground mb-1 block">Branch</label>
              <Input
                id="admin-branch-filter"
                placeholder="Filter by branch..."
                value={filter.branch}
                onChange={(e) => updateFilter({ branch: e.target.value })}
                className="w-48"
              />
            </div>
          </ArchiveFilterBar>

          {renderContent()}
        </CardContent>
      </Card>
    </div>
  )
}
