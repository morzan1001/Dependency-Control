import { useMemo, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { GitBranch, PackageSearch } from 'lucide-react'
import { useProjectBranches } from '@/hooks/queries/use-projects'
import { useInventoryStats } from '@/hooks/queries/use-inventory'
import { formatDateTime, shortCommitHash } from '@/lib/utils'
import { InventoryStatCards } from './InventoryStatCards'

interface ProjectInventoryProps {
  projectId: string
  projectName: string
  defaultBranch?: string | null
}

// Renamed with underscore to satisfy noUnusedParameters until the table children consume it for export filenames.
export function ProjectInventory({ projectId, projectName: _projectName, defaultBranch }: ProjectInventoryProps) {
  const { data: branches } = useProjectBranches(projectId)
  const activeBranches = useMemo(() => branches?.filter(b => b.is_active).map(b => b.name) || [], [branches])

  const [selectedBranch, setSelectedBranch] = useState<string | undefined>(undefined)
  const fallbackBranch = defaultBranch && activeBranches.includes(defaultBranch) ? defaultBranch : activeBranches[0]
  const branch = selectedBranch ?? fallbackBranch

  const { data: stats, isLoading, isError } = useInventoryStats(projectId, branch)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {stats && (
            <>Latest scan: {formatDateTime(stats.scan.created_at)}
              {stats.scan.commit_hash && <> · <span className="font-mono">{shortCommitHash(stats.scan.commit_hash)}</span></>}
            </>
          )}
        </div>
        <Select value={branch} onValueChange={setSelectedBranch}>
          <SelectTrigger className="w-[220px]">
            <GitBranch className="mr-2 h-4 w-4 text-muted-foreground" />
            <SelectValue placeholder="Select branch" />
          </SelectTrigger>
          <SelectContent>
            {activeBranches.map((name) => (
              <SelectItem key={name} value={name}>{name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isError ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
            <PackageSearch className="h-8 w-8 text-muted-foreground" />
            <p className="font-medium">No completed scan on this branch</p>
            <p className="text-sm text-muted-foreground">
              Run a pipeline on {branch ?? 'a branch'} to populate the inventory.
            </p>
          </CardContent>
        </Card>
      ) : (
        <InventoryStatCards stats={stats} isLoading={isLoading} />
      )}
    </div>
  )
}
