import { AlertTriangle, Rocket } from 'lucide-react'
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
import { useReleaseEnvironments } from '@/hooks/queries/use-releases'
import { useDialogState } from '@/hooks/use-dialog-state'
import { useReleaseActions } from '@/hooks/use-release-actions'
import { DEFAULT_RELEASE_ENVIRONMENT, RELEASE_ENVIRONMENT_PATTERN, RELEASE_VERSION_MAX_LENGTH } from '@/lib/constants'
import type { ScanWithReleases } from '@/types/scan'

const MARK_BUTTON = 'Mark as release'
const ENVIRONMENT_LABEL = 'Environment to release to'
const ENVIRONMENT_SUGGESTIONS = 'release-environment-suggestions'
const REJECTION_HINT_ID = 'release-environment-rejection'
const VERSION_LIKE_HINT_ID = 'release-environment-version-like'
const VERSION_LABEL = 'Version'
const VERSION_PLACEHOLDER = 'e.g. 1.0.6'
const OFF_PATTERN_HINT = 'Lowercase letters, digits, - and _ only, up to 32 characters.'
const VERSION_LIKE_HINT = 'This looks like a version number. Put it under Version and name the environment here, such as production.'
// 1.0.6, 1-0-6, v2.3, 1_0_6: a version typed into the environment, its dots swapped for the slug's dashes.
const VERSION_LIKE = /^v?\d+(?:[._-]\d+)+/i
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

export function MarkReleaseButton({ projectId, scan }: Readonly<MarkReleaseButtonProps>) {
  // Empty means the default: a datalist offers only the options containing the field's value.
  const [environment, setEnvironment] = useState('')
  const [version, setVersion] = useState('')
  const { open, setOpen, closeDialog } = useDialogState()
  const { mark, markPending } = useReleaseActions(projectId, scan)
  const { data: projectEnvironments = [] } = useReleaseEnvironments(projectId, open && !scan.is_rescan)

  const target = environment || DEFAULT_RELEASE_ENVIRONMENT
  const rejection = rejectionFor(target, scan.releases.map((release) => release.environment))
  const versionLike = VERSION_LIKE.test(environment)
  const hintIds = [rejection && REJECTION_HINT_ID, versionLike && VERSION_LIKE_HINT_ID].filter(Boolean).join(' ')
  const suggestions = [...new Set([DEFAULT_RELEASE_ENVIRONMENT, ...projectEnvironments])].filter(
    (name) => !VERSION_LIKE.test(name),
  )

  const openMarkDialog = () => {
    // The scan prop can change without a remount, so the tag is read on opening.
    const tag = scan.commit_tag ?? ''
    setVersion(tag.length <= RELEASE_VERSION_MAX_LENGTH ? tag : '')
    setOpen(true)
  }

  return (
    <>
      <Button variant="outline" disabled={!scan.commit_hash} onClick={openMarkDialog}>
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
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                <Label htmlFor="release-environment">{ENVIRONMENT_LABEL}</Label>
                <Input
                  id="release-environment"
                  aria-label={ENVIRONMENT_LABEL}
                  aria-invalid={rejection?.malformed === true}
                  aria-describedby={hintIds || undefined}
                  list={ENVIRONMENT_SUGGESTIONS}
                  placeholder={DEFAULT_RELEASE_ENVIRONMENT}
                  value={environment}
                  onChange={(event) => setEnvironment(event.target.value)}
                />
                <datalist id={ENVIRONMENT_SUGGESTIONS}>
                  {suggestions.map((name) => (
                    <option key={name} value={name} />
                  ))}
                </datalist>
                {rejection && (
                  <span
                    id={REJECTION_HINT_ID}
                    className={`text-xs ${rejection.malformed ? 'text-destructive' : 'text-muted-foreground'}`}
                  >
                    {rejection.reason}
                  </span>
                )}
                {versionLike && (
                  <span id={VERSION_LIKE_HINT_ID} className="flex items-start gap-1.5 text-xs text-muted-foreground">
                    <AlertTriangle className="mt-px h-3 w-3 shrink-0 text-warning" />
                    {VERSION_LIKE_HINT}
                  </span>
                )}
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="release-version">{VERSION_LABEL}</Label>
                <Input
                  id="release-version"
                  maxLength={RELEASE_VERSION_MAX_LENGTH}
                  placeholder={scan.commit_tag || VERSION_PLACEHOLDER}
                  value={version}
                  onChange={(event) => setVersion(event.target.value)}
                />
              </div>
            </div>
          )}
          {!scan.is_rescan && (
            <DialogFooter>
              <Button
                disabled={!scan.commit_hash || markPending || rejection !== null}
                onClick={() => mark(target, version, closeDialog)}
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
