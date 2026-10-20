import { useState } from 'react'
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Pagination } from '@/components/ui/pagination'
import { Skeleton } from '@/components/ui/skeleton'
import { Download } from 'lucide-react'
import { useInventoryCrypto } from '@/hooks/queries/use-inventory'
import { inventoryApi } from '@/api/inventory'
import { downloadServerFile } from '@/lib/download'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'

export const NO_CRYPTO_IN_CBOM = 'No cryptography found in the latest CBOM'
export const NO_CBOM = 'No CBOM uploaded for the latest scan'

interface CryptoTableProps {
  projectId: string
  branch?: string
  cbomEvaluated?: boolean
}

export function CryptoTable({ projectId, branch, cbomEvaluated }: Readonly<CryptoTableProps>) {
  const [page, setPage] = useState(1)
  const [pageBranch, setPageBranch] = useState(branch)
  if (pageBranch !== branch) {
    setPageBranch(branch)
    setPage(1)
  }

  const { data, isPending, isError, isPlaceholderData, refetch } = useInventoryCrypto(projectId, branch, {
    page, pageSize: DEFAULT_PAGE_SIZE,
  })

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1

  const handleDownload = () => downloadServerFile(
    () => inventoryApi.exportTable(projectId, 'crypto', branch),
    'crypto.csv',
    'Failed to download crypto CSV',
  )

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between space-y-0">
        <div>
          <CardTitle>Cryptography</CardTitle>
          <CardDescription>Cryptographic assets detected on this branch.</CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={handleDownload}>
          <Download className="mr-2 h-4 w-4" />
          Download CSV
        </Button>
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
            <TableBody className={isPlaceholderData ? 'opacity-60' : undefined}>
              {isPending && ['ca1', 'ca2', 'ca3'].map((id) => (
                <TableRow key={id}>
                  {['n', 't', 'p', 'v', 'k', 'l'].map((c) => (
                    <TableCell key={c}><Skeleton className="h-5 w-20" /></TableCell>
                  ))}
                </TableRow>
              ))}
              {!isPending && !isError && data?.items.map((item, index) => (
                <TableRow key={`${item.name}-${item.asset_type}-${index}`}>
                  <TableCell className="font-medium">{item.name}</TableCell>
                  <TableCell><Badge variant="secondary">{item.asset_type}</Badge></TableCell>
                  <TableCell>{item.primitive}</TableCell>
                  <TableCell className="font-mono text-xs">{item.variant}</TableCell>
                  <TableCell>{item.key_size_bits ?? ''}</TableCell>
                  <TableCell title={item.locations.join('\n')}>{item.location_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {!isPending && isError && (
            <div className="flex flex-col items-center gap-2 px-4 py-8 text-center text-sm text-muted-foreground">
              <span>Failed to load crypto assets.</span>
              <Button variant="outline" size="sm" onClick={() => refetch()}>Retry</Button>
            </div>
          )}
          {!isPending && !isError && data?.items.length === 0 && cbomEvaluated !== undefined && (
            <p className="px-4 py-8 text-center text-sm text-muted-foreground">{cbomEvaluated ? NO_CRYPTO_IN_CBOM : NO_CBOM}.</p>
          )}
        </div>
        <Pagination page={page} totalPages={totalPages} nextDisabled={isPlaceholderData} onChange={setPage} />
      </CardContent>
    </Card>
  )
}
