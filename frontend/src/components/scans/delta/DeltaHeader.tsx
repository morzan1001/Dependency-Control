import { useQuery } from '@tanstack/react-query'
import { ArrowLeftRight, GitBranch, GitCommit, Rocket } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { scanApi } from '@/api/scans'
import { useProjectReleases } from '@/hooks/queries/use-releases'
import { useProjectScans } from '@/hooks/queries/use-scans'
import { formatDateTime, shortCommitHash } from '@/lib/utils'
import { isScanUsable } from '@/lib/scan-status'
import type { ReleaseItem } from '@/types/release'
import { Scan } from '@/types/scan'

const LATEST_RELEASE_LIMIT = 1
const RELEASE_MARKER_LABEL = 'Release'

interface DeltaHeaderProps {
  projectId: string
  fromScanId: string
  toScanId: string
  onChange: (from: string, to: string) => void
}

function ScanLabel({ scan }: { readonly scan: Scan }) {
  const pipeline = scan.pipeline_iid ? `#${scan.pipeline_iid} · ` : ''
  return (
    <span className="flex items-center gap-1">
      {`${pipeline}${scan.branch} · ${formatDateTime(scan.created_at)}`}
      {/* An icon, not a word: the select trigger has a fixed width and would clip the label. */}
      {scan.is_release && (
        <Rocket role="img" aria-label={RELEASE_MARKER_LABEL} className="h-3 w-3 shrink-0 text-success" />
      )}
    </span>
  )
}

function releaseHint(release: ReleaseItem, alreadyCompared: boolean): string {
  if (release.analysis_scan_id === null) {
    return `The ${release.environment} release has no readable scan to compare.`
  }
  if (alreadyCompared) return `Already comparing the ${release.environment} release.`
  const version = release.version ? ` ${release.version}` : ''
  return `Compares the ${release.environment} release${version} against the To scan.`
}

function ScanSide({ label, scanId, options, onSelect }: {
  readonly label: string
  readonly scanId: string
  readonly options: Scan[]
  readonly onSelect: (id: string) => void
}) {
  const { data: scan } = useQuery({ queryKey: ['scan', scanId], queryFn: () => scanApi.getOne(scanId) })
  // The compared scan can be a rescan or a release older than the option window; without this
  // fallback the trigger renders blank.
  const currentInOptions = options.some((option) => option.id === scanId)
  return (
    <div className="flex-1 space-y-2">
      <p className="text-xs font-medium uppercase text-muted-foreground">{label}</p>
      <Select value={scanId} onValueChange={onSelect}>
        <SelectTrigger><SelectValue /></SelectTrigger>
        <SelectContent>
          {scan && !currentInOptions && (
            <SelectItem value={scanId}><ScanLabel scan={scan} /></SelectItem>
          )}
          {options.map((option) => (
            <SelectItem key={option.id} value={option.id}><ScanLabel scan={option} /></SelectItem>
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
  const options = (scans || []).filter((s) => isScanUsable(s.status))
  // The endpoint sorts releases newest first, so a single row is the newest one and no page
  // size can hide it — the quick pick never needs the rest of the project's release history.
  const { data: releases } = useProjectReleases(projectId, undefined, LATEST_RELEASE_LIMIT)
  const latestRelease = releases?.items[0]
  // A rescan moves a release's analysis onto a newer scan and the backend's own `from=release`
  // follows that chain, so `scan_id` would diff against findings the release no longer reports.
  // Null means nothing in the chain is readable — retention took it, or none of it has finished.
  const releaseScanId = latestRelease?.analysis_scan_id ?? null
  const alreadyCompared = releaseScanId !== null
    && (releaseScanId === fromScanId || releaseScanId === toScanId)

  return (
    <Card>
      <CardContent className="flex flex-col gap-3 pt-6">
        {latestRelease && (
          <div className="flex flex-wrap items-center gap-2">
            {releaseScanId !== null && (
              <Button
                variant="outline"
                size="sm"
                className="w-fit shrink-0"
                disabled={alreadyCompared}
                onClick={() => onChange(releaseScanId, toScanId)}
              >
                <Rocket className="mr-2 h-3 w-3" />
                Latest release
              </Button>
            )}
            <span className="text-xs text-muted-foreground">
              {releaseHint(latestRelease, alreadyCompared)}
            </span>
          </div>
        )}
        <div className="flex items-end gap-4">
          <ScanSide label="From" scanId={fromScanId} options={options}
            onSelect={(id) => id !== toScanId && onChange(id, toScanId)} />
          <Button variant="outline" size="icon" className="shrink-0"
            onClick={() => onChange(toScanId, fromScanId)} aria-label="Swap scans">
            <ArrowLeftRight className="h-4 w-4" />
          </Button>
          <ScanSide label="To" scanId={toScanId} options={options}
            onSelect={(id) => id !== fromScanId && onChange(fromScanId, id)} />
        </div>
      </CardContent>
    </Card>
  )
}
