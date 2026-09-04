import { Rocket } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'

import { ReleaseBadge } from '@/components/scans/ReleaseBadge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useMarkRelease, useUnmarkRelease } from '@/hooks/queries/use-releases'
import { DEFAULT_RELEASE_ENVIRONMENT, RELEASE_ENVIRONMENT_PATTERN } from '@/lib/constants'
import { formatDateTime } from '@/lib/utils'
import type { ScanWithReleases } from '@/types/scan'

const ENVIRONMENT_LABEL = 'Environment to release to'
const OFF_PATTERN_HINT = 'Lowercase letters, digits, - and _ only, up to 32 characters.'
const RESCAN_NOTE = 'A re-scan carries the same commit, so its releases are held by the original scan.'
const ORIGINAL_SCAN_LINK = 'Open the original scan'
const SECTION_LABEL = 'Release'

interface ScanReleaseControlProps {
  projectId: string
  scan: ScanWithReleases
}

interface MarkRejection {
  reason: string
  // An environment the scan already holds is a fine value badly timed, not a malformed one.
  malformed: boolean
}

function rejectionFor(environment: string, held: readonly string[]): MarkRejection | null {
  if (!RELEASE_ENVIRONMENT_PATTERN.test(environment)) return { reason: OFF_PATTERN_HINT, malformed: true }
  // The backend would upsert the same record; offering that only invites confusion.
  if (held.includes(environment)) return { reason: `Already released to ${environment}.`, malformed: false }
  return null
}

export function ScanReleaseControl({ projectId, scan }: ScanReleaseControlProps) {
  const [environment, setEnvironment] = useState(DEFAULT_RELEASE_ENVIRONMENT)
  const markRelease = useMarkRelease()
  const unmarkRelease = useUnmarkRelease()

  // mark_release resolves the commit to the scan that is not a re-scan, so a mark taken here would
  // land on a record this page can never show.
  if (scan.is_rescan) {
    return (
      <div className="flex flex-col space-y-1">
        <span className="text-sm text-muted-foreground">{SECTION_LABEL}</span>
        <span className="text-xs text-muted-foreground">{RESCAN_NOTE}</span>
        {scan.original_scan_id && (
          <Link
            to={`/projects/${projectId}/scans/${scan.original_scan_id}`}
            className="w-fit text-xs text-primary hover:underline"
          >
            {ORIGINAL_SCAN_LINK}
          </Link>
        )}
      </div>
    )
  }

  const rejection = rejectionFor(environment, scan.releases.map((release) => release.environment))

  const handleMark = () => {
    if (!scan.commit_hash) return
    markRelease.mutate(
      // No version: the backend falls back to the scan's commit_tag, which is what CI built.
      { projectId, payload: { commit_hash: scan.commit_hash, environment } },
      {
        onSuccess: () => toast.success(`Marked as release in ${environment}`),
        onError: () => toast.error(`Could not mark this scan as a release in ${environment}`),
      },
    )
  }

  const handleUnmark = (withdrawnFrom: string) => {
    unmarkRelease.mutate(
      { projectId, scanId: scan.id, environment: withdrawnFrom },
      {
        onSuccess: () => toast.success(`Withdrawn from ${withdrawnFrom}`),
        onError: () => toast.error(`Could not withdraw this scan from ${withdrawnFrom}`),
      },
    )
  }

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
              disabled={unmarkRelease.isPending}
              onClick={() => handleUnmark(release.environment)}
            >
              Withdraw from {release.environment}
            </Button>
          </div>
        ))}
        {/* The flag denormalises the release records, so one without them is still a release. */}
        {scan.is_release && scan.releases.length === 0 && <ReleaseBadge />}
        <div className="flex flex-col gap-1">
          <Input
            aria-label={ENVIRONMENT_LABEL}
            aria-invalid={rejection?.malformed === true}
            value={environment}
            onChange={(event) => setEnvironment(event.target.value)}
            className="h-8 w-full max-w-[12rem] text-xs"
          />
          <Button
            variant="outline"
            size="sm"
            className="w-fit"
            disabled={!scan.commit_hash || markRelease.isPending || rejection !== null}
            onClick={handleMark}
          >
            <Rocket className="mr-2 h-3 w-3" />
            Mark as release
          </Button>
          {rejection && (
            <span className={`text-xs ${rejection.malformed ? 'text-destructive' : 'text-muted-foreground'}`}>
              {rejection.reason}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
