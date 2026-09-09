import { Rocket } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useDialogState } from '@/hooks/use-dialog-state'
import { useReleaseActions } from '@/hooks/use-release-actions'
import { DEFAULT_RELEASE_ENVIRONMENT, RELEASE_ENVIRONMENT_PATTERN } from '@/lib/constants'
import type { ScanWithReleases } from '@/types/scan'

const MARK_BUTTON = 'Mark as release'
const ENVIRONMENT_LABEL = 'Environment to release to'
const OFF_PATTERN_HINT = 'Lowercase letters, digits, - and _ only, up to 32 characters.'
const RESCAN_NOTE = 'A re-scan carries the same commit, so its releases are held by the original scan.'
const ORIGINAL_SCAN_LINK = 'Open the original scan'
const DIALOG_DESCRIPTION = 'Records this build as the artefact running in an environment.'

interface MarkReleaseButtonProps {
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

export function MarkReleaseButton({ projectId, scan }: MarkReleaseButtonProps) {
  const [environment, setEnvironment] = useState(DEFAULT_RELEASE_ENVIRONMENT)
  const { open, setOpen, closeDialog } = useDialogState()
  const { mark, markPending } = useReleaseActions(projectId, scan)

  const rejection = rejectionFor(environment, scan.releases.map((release) => release.environment))

  return (
    <>
      <Button variant="outline" disabled={!scan.commit_hash} onClick={() => setOpen(true)}>
        <Rocket className="mr-2 h-4 w-4" />
        {MARK_BUTTON}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{MARK_BUTTON}</DialogTitle>
            <DialogDescription>{scan.is_rescan ? RESCAN_NOTE : DIALOG_DESCRIPTION}</DialogDescription>
          </DialogHeader>
          {/* mark_release resolves the commit to the scan that is not a re-scan, so a mark taken
              here would land on a record this page can never show. */}
          {scan.is_rescan ? (
            scan.original_scan_id && (
              <Link
                to={`/projects/${projectId}/scans/${scan.original_scan_id}`}
                className="text-sm text-primary hover:underline"
                onClick={closeDialog}
              >
                {ORIGINAL_SCAN_LINK}
              </Link>
            )
          ) : (
            <div className="flex flex-col gap-2">
              <Label htmlFor="release-environment">{ENVIRONMENT_LABEL}</Label>
              <Input
                id="release-environment"
                aria-label={ENVIRONMENT_LABEL}
                aria-invalid={rejection?.malformed === true}
                value={environment}
                onChange={(event) => setEnvironment(event.target.value)}
              />
              {rejection && (
                <span className={`text-xs ${rejection.malformed ? 'text-destructive' : 'text-muted-foreground'}`}>
                  {rejection.reason}
                </span>
              )}
            </div>
          )}
          {!scan.is_rescan && (
            <DialogFooter>
              <Button
                disabled={!scan.commit_hash || markPending || rejection !== null}
                onClick={() => mark(environment, closeDialog)}
              >
                <Rocket className="mr-2 h-4 w-4" />
                {MARK_BUTTON}
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
