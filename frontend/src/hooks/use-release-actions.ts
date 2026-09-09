import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'

import { useMarkRelease, useUnmarkRelease } from '@/hooks/queries/use-releases'
import { formatDateTime } from '@/lib/utils'
import type { ScanWithReleases } from '@/types/scan'

const MARKED_SCAN_LINK = 'Open the marked scan'
// Long enough to read which scan took the mark and reach the link.
const MARKED_ELSEWHERE_TOAST_MS = 15_000
const UNCOVERED_RELEASE_TOAST_MS = 15_000
const UNCOVERED_SCAN_LINK = 'Open that release'

export interface ReleaseActions {
  mark: (environment: string, onMarked?: () => void) => void
  withdraw: (environment: string) => void
  markPending: boolean
  withdrawPending: boolean
}

export function useReleaseActions(projectId: string, scan: ScanWithReleases): ReleaseActions {
  const navigate = useNavigate()
  const markRelease = useMarkRelease()
  const unmarkRelease = useUnmarkRelease()

  const mark = (environment: string, onMarked?: () => void) => {
    if (!scan.commit_hash) return
    markRelease.mutate(
      // No version: the backend falls back to the scan's commit_tag, which is what CI built.
      { projectId, payload: { commit_hash: scan.commit_hash, environment } },
      {
        onSuccess: (release) => {
          onMarked?.()
          // The mark resolves the commit to its newest analysis, and a re-run pipeline on the same
          // commit makes a second one, so the row can land on a scan other than the one open here.
          if (release.scan_id === scan.id) {
            toast.success(`Marked as release in ${environment}`)
            return
          }
          toast.success(`Marked as release in ${environment}, on a newer scan of this commit`, {
            description: `Recorded against scan ${release.scan_id}, which this page is not showing.`,
            duration: MARKED_ELSEWHERE_TOAST_MS,
            action: {
              label: MARKED_SCAN_LINK,
              onClick: () => navigate(`/projects/${projectId}/scans/${release.scan_id}`),
            },
          })
        },
        onError: () => toast.error(`Could not mark this scan as a release in ${environment}`),
      },
    )
  }

  const withdraw = (withdrawnFrom: string) => {
    unmarkRelease.mutate(
      { projectId, scanId: scan.id, environment: withdrawnFrom },
      {
        onSuccess: (response) => {
          // Marks are history, so a withdrawal can uncover an older one and leave the environment
          // reporting a build nobody chose to deploy.
          const uncovered = response.environment_release
          if (!uncovered) {
            toast.success(`Withdrawn from ${withdrawnFrom}`)
            return
          }
          toast.warning(`Withdrawn from ${withdrawnFrom}, which now reports an earlier release`, {
            description:
              `${withdrawnFrom} is now ${uncovered.version ?? uncovered.scan_id}, released `
              + `${formatDateTime(uncovered.released_at)}. Withdraw it too if nothing is deployed there.`,
            duration: UNCOVERED_RELEASE_TOAST_MS,
            action: {
              label: UNCOVERED_SCAN_LINK,
              onClick: () => navigate(`/projects/${projectId}/scans/${uncovered.scan_id}`),
            },
          })
        },
        onError: () => toast.error(`Could not withdraw this scan from ${withdrawnFrom}`),
      },
    )
  }

  return { mark, withdraw, markPending: markRelease.isPending, withdrawPending: unmarkRelease.isPending }
}
