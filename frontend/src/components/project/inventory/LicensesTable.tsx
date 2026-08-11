import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Download } from 'lucide-react'
import { useInventoryLicenses } from '@/hooks/queries/use-inventory'
import { inventoryApi } from '@/api/inventory'
import { downloadFile } from '@/lib/download'

interface LicensesTableProps {
  projectId: string
  projectName: string
  branch?: string
}

const CATEGORY_CLASSES: Record<string, string> = {
  permissive: '',
  weak_copyleft: 'border-yellow-500/20 bg-yellow-500/10 text-yellow-600',
  strong_copyleft: 'border-red-500/20 bg-red-500/10 text-red-600',
}

function CategoryBadge({ category }: { readonly category?: string | null }) {
  if (!category) return <span className="text-muted-foreground">—</span>
  return (
    <Badge variant="secondary" className={CATEGORY_CLASSES[category] ?? ''}>
      {category.replaceAll('_', ' ')}
    </Badge>
  )
}

export function LicensesTable({ projectId, projectName, branch }: LicensesTableProps) {
  const { data, isLoading } = useInventoryLicenses(projectId, branch)

  const handleDownload = () => downloadFile(
    () => inventoryApi.exportTable(projectId, 'licenses', branch),
    `${projectName}_licenses_${branch}_${new Date().toISOString().slice(0, 10)}.csv`,
    'Failed to download licenses CSV',
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Licenses</CardTitle>
            <CardDescription>License categories and risk notes across components on this branch.</CardDescription>
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
                <TableHead>License</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Risks</TableHead>
                <TableHead className="text-right">Components</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && ['l1', 'l2', 'l3'].map((id) => (
                <TableRow key={id}>
                  {['li', 'c', 'r', 'n'].map((c) => (
                    <TableCell key={c}><Skeleton className="h-5 w-20" /></TableCell>
                  ))}
                </TableRow>
              ))}
              {!isLoading && data?.items.map((item) => (
                <TableRow key={item.license}>
                  <TableCell className="font-medium">{item.license}</TableCell>
                  <TableCell><CategoryBadge category={item.category} /></TableCell>
                  <TableCell className="max-w-[320px] truncate text-muted-foreground" title={item.risks.join('; ')}>
                    {item.risks.join('; ')}
                  </TableCell>
                  <TableCell className="text-right">{item.component_count}</TableCell>
                </TableRow>
              ))}
              {!isLoading && (data?.items.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="py-8 text-center text-muted-foreground">
                    No licenses found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}
