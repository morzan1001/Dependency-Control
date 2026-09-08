import { ReleaseBadge } from '@/components/scans/ReleaseBadge'
import { Button } from '@/components/ui/button'
import { useReleaseActions } from '@/hooks/use-release-actions'
import { hasUnrecordedRelease } from '@/lib/releases'
import { formatDateTime } from '@/lib/utils'
import type { ScanWithReleases } from '@/types/scan'

const SECTION_LABEL = 'Release'

interface ScanReleaseControlProps {
  projectId: string
  scan: ScanWithReleases
}

export function ScanReleaseControl({ projectId, scan }: ScanReleaseControlProps) {
  const { withdraw, withdrawPending } = useReleaseActions(projectId, scan)

  // A re-scan's releases are held by the original scan, so this panel would be empty or wrong;
  // MarkReleaseButton explains that and links there.
  const unrecorded = !scan.is_rescan && hasUnrecordedRelease(scan)
  if (scan.is_rescan || (scan.releases.length === 0 && !unrecorded)) return null

  return (
    <div className="flex flex-col space-y-1">
      <span className="text-sm text-muted-foreground">{SECTION_LABEL}</span>
      <div className="flex flex-col gap-2">
        {scan.releases.map((release) => (
          <div key={release.environment} className="flex flex-col gap-0.5">
            <ReleaseBadge environment={release.environment} version={release.version} />
            <span className="text-xs text-muted-foreground">Released {formatDateTime(release.released_at)}</span>
            <Button
              variant="ghost"
              size="sm"
              className="w-fit px-0 text-xs"
              disabled={withdrawPending}
              onClick={() => withdraw(release.environment)}
            >
              Withdraw from {release.environment}
            </Button>
          </div>
        ))}
        {unrecorded && <ReleaseBadge />}
      </div>
    </div>
  )
}
