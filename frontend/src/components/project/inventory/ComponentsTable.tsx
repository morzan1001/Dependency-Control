import { useState } from 'react'
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, Download } from 'lucide-react'
import { useInventoryComponents } from '@/hooks/queries/use-inventory'
import { inventoryApi } from '@/api/inventory'
import { downloadFile } from '@/lib/download'
import { ComponentItem } from '@/types/inventory'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'

interface ComponentsTableProps {
  projectId: string
  projectName: string
  branch?: string
}

function LifecycleBadge({ item }: { readonly item: ComponentItem }) {
  if (item.eol) return <Badge variant="destructive">EOL</Badge>
  if (item.outdated) {
    return (
      <Badge variant="secondary" className="border-yellow-500/20 bg-yellow-500/10 text-yellow-600">
        Outdated
      </Badge>
    )
  }
  return <span className="text-muted-foreground">—</span>
}

export function ComponentsTable({ projectId, projectName, branch }: ComponentsTableProps) {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('name')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc')

  const { data, isPending, isError, isPlaceholderData, refetch } = useInventoryComponents(projectId, branch, {
    page, pageSize: DEFAULT_PAGE_SIZE, search: search || undefined, sortBy, sortOrder,
  })

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1

  const handleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(column)
      setSortOrder('asc')
    }
    setPage(1)
  }

  const renderSortIcon = (column: string) => {
    if (sortBy !== column) return null
    return sortOrder === 'asc' ? <ArrowUp className="ml-2 inline h-4 w-4" /> : <ArrowDown className="ml-2 inline h-4 w-4" />
  }

  const handleDownload = () => downloadFile(
    () => inventoryApi.exportTable(projectId, 'components', branch),
    `${projectName}_components_${branch}_${new Date().toISOString().slice(0, 10)}.csv`,
    'Failed to download components CSV',
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Components</CardTitle>
            <CardDescription>Software in use on this branch, with license and lifecycle status.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Input
              placeholder="Search components…"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1) }}
              className="w-[220px]"
            />
            <Button variant="outline" size="sm" onClick={handleDownload}>
              <Download className="mr-2 h-4 w-4" />
              Download CSV
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('name')}>
                  Name {renderSortIcon('name')}
                </TableHead>
                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('version')}>
                  Version {renderSortIcon('version')}
                </TableHead>
                <TableHead>Latest</TableHead>
                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('type')}>
                  Ecosystem {renderSortIcon('type')}
                </TableHead>
                <TableHead className="cursor-pointer hover:text-foreground" onClick={() => handleSort('license')}>
                  License {renderSortIcon('license')}
                </TableHead>
                <TableHead>Direct</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody className={isPlaceholderData ? 'opacity-60' : undefined}>
              {isPending && ['c1', 'c2', 'c3'].map((id) => (
                <TableRow key={id}>
                  {['n', 'v', 'l', 'e', 'li', 'd', 's'].map((c) => (
                    <TableCell key={c}><Skeleton className="h-5 w-20" /></TableCell>
                  ))}
                </TableRow>
              ))}
              {!isPending && isError && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    <div className="flex flex-col items-center gap-2">
                      <span>Failed to load components.</span>
                      <Button variant="outline" size="sm" onClick={() => refetch()}>Retry</Button>
                    </div>
                  </TableCell>
                </TableRow>
              )}
              {!isPending && !isError && data?.items.map((item) => (
                <TableRow key={item.purl ?? `${item.name}@${item.version}`}>
                  <TableCell className="font-medium">{item.name}</TableCell>
                  <TableCell className="font-mono text-xs">{item.version}</TableCell>
                  <TableCell className="font-mono text-xs">{item.latest_version ?? ''}</TableCell>
                  <TableCell><Badge variant="secondary">{item.ecosystem}</Badge></TableCell>
                  <TableCell>{item.license ?? <span className="text-muted-foreground">unknown</span>}</TableCell>
                  <TableCell>{item.direct && <Badge variant="outline">direct</Badge>}</TableCell>
                  <TableCell><LifecycleBadge item={item} /></TableCell>
                </TableRow>
              ))}
              {!isPending && !isError && data?.items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    No components found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-end gap-2 py-4 text-sm text-muted-foreground">
            Page {data?.page ?? 1} of {totalPages}
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft className="h-4 w-4" /> Previous
            </Button>
            <Button variant="outline" size="sm" disabled={page >= totalPages || isPlaceholderData} onClick={() => setPage(p => p + 1)}>
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
