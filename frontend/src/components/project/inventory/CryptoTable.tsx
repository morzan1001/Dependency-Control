import { useState } from 'react'
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ChevronLeft, ChevronRight, Download } from 'lucide-react'
import { useInventoryCrypto } from '@/hooks/queries/use-inventory'
import { inventoryApi } from '@/api/inventory'
import { downloadFile } from '@/lib/download'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'

interface CryptoTableProps {
  projectId: string
  projectName: string
  branch?: string
}

export function CryptoTable({ projectId, projectName, branch }: CryptoTableProps) {
  const [page, setPage] = useState(1)

  const { data, isLoading, isPlaceholderData } = useInventoryCrypto(projectId, branch, {
    page, pageSize: DEFAULT_PAGE_SIZE,
  })

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1

  const handleDownload = () => downloadFile(
    () => inventoryApi.exportTable(projectId, 'crypto', branch),
    `${projectName}_crypto_${branch}_${new Date().toISOString().slice(0, 10)}.csv`,
    'Failed to download crypto CSV',
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Cryptography</CardTitle>
            <CardDescription>Cryptographic assets detected on this branch.</CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={handleDownload}>
            <Download className="mr-2 h-4 w-4" />
            Download CSV
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Primitive</TableHead>
                <TableHead>Variant</TableHead>
                <TableHead>Key size</TableHead>
                <TableHead>Locations</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && ['ca1', 'ca2', 'ca3'].map((id) => (
                <TableRow key={id}>
                  {['n', 't', 'p', 'v', 'k', 'l'].map((c) => (
                    <TableCell key={c}><Skeleton className="h-5 w-20" /></TableCell>
                  ))}
                </TableRow>
              ))}
              {!isLoading && data?.items.map((item, index) => (
                <TableRow key={`${item.name}-${item.asset_type}-${index}`}>
                  <TableCell className="font-medium">{item.name}</TableCell>
                  <TableCell><Badge variant="secondary">{item.asset_type}</Badge></TableCell>
                  <TableCell>{item.primitive}</TableCell>
                  <TableCell className="font-mono text-xs">{item.variant}</TableCell>
                  <TableCell>{item.key_size_bits ?? ''}</TableCell>
                  <TableCell title={item.locations.join('\n')}>{item.location_count}</TableCell>
                </TableRow>
              ))}
              {!isLoading && (data?.items.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                    No cryptographic assets found.
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
