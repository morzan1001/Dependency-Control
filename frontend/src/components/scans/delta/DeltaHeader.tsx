import { useQuery } from '@tanstack/react-query'
import { ArrowLeftRight, GitBranch, GitCommit } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { scanApi } from '@/api/scans'
import { useProjectScans } from '@/hooks/queries/use-scans'
import { formatDateTime, shortCommitHash } from '@/lib/utils'
import { Scan } from '@/types/scan'

interface DeltaHeaderProps {
  projectId: string
  fromScanId: string
  toScanId: string
  onChange: (from: string, to: string) => void
}

function scanLabel(scan: Scan): string {
  const pipeline = scan.pipeline_iid ? `#${scan.pipeline_iid} · ` : ''
  return `${pipeline}${scan.branch} · ${formatDateTime(scan.created_at)}`
}

function ScanSide({ label, scanId, options, onSelect }: {
  readonly label: string
  readonly scanId: string
  readonly options: Scan[]
  readonly onSelect: (id: string) => void
}) {
  const { data: scan } = useQuery({ queryKey: ['scan', scanId], queryFn: () => scanApi.getOne(scanId) })
  return (
    <div className="flex-1 space-y-2">
      <p className="text-xs font-medium uppercase text-muted-foreground">{label}</p>
      <Select value={scanId} onValueChange={onSelect}>
        <SelectTrigger><SelectValue /></SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.id} value={option.id}>{scanLabel(option)}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      {scan && (
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1"><GitBranch className="h-3 w-3" />{scan.branch}</span>
          {scan.commit_hash && (
            <span className="flex items-center gap-1 font-mono">
              <GitCommit className="h-3 w-3" />{shortCommitHash(scan.commit_hash)}
            </span>
          )}
          <span>{formatDateTime(scan.created_at)}</span>
        </div>
      )}
    </div>
  )
}

export function DeltaHeader({ projectId, fromScanId, toScanId, onChange }: DeltaHeaderProps) {
  const { data: scans } = useProjectScans(projectId, { page: 1, limit: 50, excludeRescans: true })
  const options = (scans || []).filter((s) => s.status === 'completed')

  return (
    <Card>
      <CardContent className="flex items-end gap-4 pt-6">
        <ScanSide label="From" scanId={fromScanId} options={options}
          onSelect={(id) => id !== toScanId && onChange(id, toScanId)} />
        <Button variant="outline" size="icon" className="shrink-0"
          onClick={() => onChange(toScanId, fromScanId)} aria-label="Swap scans">
          <ArrowLeftRight className="h-4 w-4" />
        </Button>
        <ScanSide label="To" scanId={toScanId} options={options}
          onSelect={(id) => id !== fromScanId && onChange(fromScanId, id)} />
      </CardContent>
    </Card>
  )
}
