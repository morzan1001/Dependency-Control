import { Rocket } from 'lucide-react'
import { toast } from 'sonner'

import { ReleaseBadge } from '@/components/scans/ReleaseBadge'
import { Button } from '@/components/ui/button'
import { useMarkRelease, useProjectReleases, useUnmarkRelease } from '@/hooks/queries/use-releases'
import { formatDateTime } from '@/lib/utils'
import type { Scan } from '@/types/scan'

interface ScanReleaseControlProps {
  projectId: string
  scan: Scan
}

export function ScanReleaseControl({ projectId, scan }: ScanReleaseControlProps) {
  // Reading one scan does not carry its release rows, so they come from the project's list.
  const { data: releases } = useProjectReleases(projectId)
  const markRelease = useMarkRelease()
  const unmarkRelease = useUnmarkRelease()

  const scanReleases = releases?.items.filter((release) => release.scan_id === scan.id) ?? []

  const handleMark = () => {
    if (!scan.commit_hash) return
    markRelease.mutate(
      { projectId, payload: { commit_hash: scan.commit_hash } },
      {
        onSuccess: () => toast.success('Marked as release'),
        onError: () => toast.error('Could not mark this scan as a release'),
      },
    )
  }

  const handleUnmark = (environment: string) => {
    unmarkRelease.mutate(
      { projectId, scanId: scan.id, environment },
      {
        onSuccess: () => toast.success(`Withdrawn from ${environment}`),
        onError: () => toast.error(`Could not withdraw this scan from ${environment}`),
      },
    )
  }

  return (
    <div className="flex flex-col space-y-1">
      <span className="text-sm text-muted-foreground">Release</span>
      {scan.is_release ? (
        <div className="flex flex-col gap-2">
          {scanReleases.map((release) => (
            <div key={release.environment} className="flex flex-col gap-0.5">
              <ReleaseBadge environment={release.environment} version={release.version} />
              <span className="text-xs text-muted-foreground">Released {formatDateTime(release.released_at)}</span>
              <Button
                variant="ghost"
                size="sm"
                className="w-fit px-0 text-xs"
                disabled={unmarkRelease.isPending}
                onClick={() => handleUnmark(release.environment)}
              >
                Withdraw from {release.environment}
              </Button>
            </div>
          ))}
          {/* Ingest sets the flag before writing the record, and the list it comes from is paged. */}
          {scanReleases.length === 0 && <ReleaseBadge />}
        </div>
      ) : (
        <Button
          variant="outline"
          size="sm"
          className="w-fit"
          disabled={!scan.commit_hash || markRelease.isPending}
          onClick={handleMark}
        >
          <Rocket className="mr-2 h-3 w-3" />
          Mark as release
        </Button>
      )}
    </div>
  )
}
