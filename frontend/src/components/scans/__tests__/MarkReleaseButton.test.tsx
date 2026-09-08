import { render, screen, fireEvent, within, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { toast } from 'sonner'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { MarkReleaseButton } from '../MarkReleaseButton'
import type { ReleaseItem } from '@/types/release'
import type { ScanReleaseRef, ScanWithReleases } from '@/types/scan'

const PROJECT_ID = 'p1'
const SCAN_ID = 'scan-1'
const ORIGINAL_SCAN_ID = 'scan-0'
const NEWER_SCAN_ID = 'scan-2'
const MARKED_SCAN_LINK = 'Open the marked scan'
const COMMIT_HASH = 'a'.repeat(40)
const PRODUCTION = 'production'
const STAGING = 'staging'
const PRODUCTION_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const PRODUCTION_RELEASED_AT = '2026-09-01T10:00:00Z'
const MARK_BUTTON = 'Mark as release'
const ENVIRONMENT_FIELD = 'Environment to release to'
const OFF_PATTERN_ENVIRONMENT = 'Pre-Prod!'
const OFF_PATTERN_HINT = /lowercase letters/i
const RESCAN_NOTE = /releases are held by the original scan/i
const ORIGINAL_SCAN_LINK = 'Open the original scan'

const mockMark = vi.fn()
const mockUnmark = vi.fn()

vi.mock('@/hooks/queries/use-releases', () => ({
  useMarkRelease: () => ({ mutate: mockMark, isPending: false }),
  useUnmarkRelease: () => ({ mutate: mockUnmark, isPending: false }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))

function makeScan(overrides: Partial<ScanWithReleases> = {}): ScanWithReleases {
  return {
    id: SCAN_ID,
    project_id: PROJECT_ID,
    branch: 'main',
    commit_hash: COMMIT_HASH,
    status: 'completed',
    created_at: '2026-09-01T00:00:00Z',
    is_release: false,
    releases: [],
    ...overrides,
  }
}

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
function markResponse(scanId: string): ReleaseItem {
  return {
    scan_id: scanId,
    project_id: PROJECT_ID,
    environment: PRODUCTION,
    version: PRODUCTION_VERSION,
    released_at: PRODUCTION_RELEASED_AT,
    commit_hash: COMMIT_HASH,
    branch: 'main',
    scan_status: 'completed',
    analysis_scan_id: scanId,
    analysis_chain_bounded: false,
  }
}

function makeRelease(overrides: Partial<ScanReleaseRef> = {}): ScanReleaseRef {
  return {
    environment: PRODUCTION,
    version: PRODUCTION_VERSION,
    released_at: PRODUCTION_RELEASED_AT,
    ...overrides,
  }
}

function releasedScan(releases: ScanReleaseRef[]): ScanWithReleases {
  return makeScan({ is_release: true, releases })
}

function renderButton(scan: ScanWithReleases) {
  return render(
    <MemoryRouter>
      <MarkReleaseButton projectId={PROJECT_ID} scan={scan} />
    </MemoryRouter>,
  )
}

/** Clicks the header trigger and scopes further queries to the dialog, which repeats its name. */
function openDialog(scan: ScanWithReleases) {
  renderButton(scan)
  fireEvent.click(screen.getByRole('button', { name: MARK_BUTTON }))
  return within(screen.getByRole('dialog'))
}

function markAndResolveTo(scanId: string) {
  const dialog = openDialog(makeScan())
  fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))
  const handlers = mockMark.mock.calls[0][1] as { onSuccess: (release: ReleaseItem) => void }
  // Resolving outside React's event system: act() flushes the close that onSuccess triggers.
  act(() => handlers.onSuccess(markResponse(scanId)))
}

beforeEach(() => vi.clearAllMocks())

describe('MarkReleaseButton', () => {
  it('keeps the page quiet until the button is pressed', () => {
    renderButton(makeScan())

    // The whole point of moving this out of the metadata card: nothing is on screen but the button.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByLabelText(ENVIRONMENT_FIELD)).not.toBeInTheDocument()
  })

  it('marks a plain scan into the default environment, leaving the version to the backend', () => {
    const dialog = openDialog(makeScan())

    fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))

    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH, environment: PRODUCTION } },
      expect.anything(),
    )
  })

  it('promotes a staging release to the environment that was typed', () => {
    const dialog = openDialog(releasedScan([makeRelease({ environment: STAGING, version: STAGING_VERSION })]))

    fireEvent.change(dialog.getByLabelText(ENVIRONMENT_FIELD), { target: { value: PRODUCTION } })
    fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))

    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH, environment: PRODUCTION } },
      expect.anything(),
    )
  })

  it('does not offer to re-mark an environment the scan already holds', () => {
    const dialog = openDialog(releasedScan([makeRelease()]))

    expect(dialog.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
    expect(dialog.getByText(`Already released to ${PRODUCTION}.`)).toBeInTheDocument()
    // An untouched field holding the default is not a value the user got wrong.
    expect(dialog.getByLabelText(ENVIRONMENT_FIELD)).not.toHaveAttribute('aria-invalid', 'true')
  })

  it('marks the field invalid only for a value the backend would refuse', () => {
    const dialog = openDialog(makeScan())

    fireEvent.change(dialog.getByLabelText(ENVIRONMENT_FIELD), { target: { value: OFF_PATTERN_ENVIRONMENT } })

    expect(dialog.getByLabelText(ENVIRONMENT_FIELD)).toHaveAttribute('aria-invalid', 'true')
  })

  it('points a re-scan at the original scan instead of offering a mark that lands elsewhere', () => {
    const dialog = openDialog(makeScan({ is_rescan: true, original_scan_id: ORIGINAL_SCAN_ID }))

    expect(dialog.getByText(RESCAN_NOTE)).toBeInTheDocument()
    expect(dialog.getByRole('link', { name: ORIGINAL_SCAN_LINK })).toHaveAttribute(
      'href',
      `/projects/${PROJECT_ID}/scans/${ORIGINAL_SCAN_ID}`,
    )
    expect(dialog.queryByRole('button', { name: MARK_BUTTON })).not.toBeInTheDocument()
    expect(dialog.queryByLabelText(ENVIRONMENT_FIELD)).not.toBeInTheDocument()
  })

  it('rejects an environment the backend would refuse instead of requesting it', () => {
    const dialog = openDialog(makeScan())

    fireEvent.change(dialog.getByLabelText(ENVIRONMENT_FIELD), { target: { value: OFF_PATTERN_ENVIRONMENT } })
    fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))

    expect(dialog.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
    expect(dialog.getByText(OFF_PATTERN_HINT)).toBeInTheDocument()
    expect(mockMark).not.toHaveBeenCalled()
  })

  it('cannot open the dialog for a scan that has no commit', () => {
    renderButton(makeScan({ commit_hash: undefined }))

    expect(screen.getByRole('button', { name: MARK_BUTTON })).toBeDisabled()
  })

  it('stays markable in every environment when it holds a release it cannot name', () => {
    // Nothing names the environments it holds, so every one of them stays markable.
    const dialog = openDialog(releasedScan([]))

    expect(dialog.getByRole('button', { name: MARK_BUTTON })).toBeEnabled()
  })

  it('confirms plainly when the mark landed on the scan on screen', () => {
    markAndResolveTo(SCAN_ID)

    expect(toast.success).toHaveBeenCalledWith(`Marked as release in ${PRODUCTION}`)
  })

  it('names the scan that took the mark when a newer analysis of the commit won it', () => {
    markAndResolveTo(NEWER_SCAN_ID)

    const [message, options] = vi.mocked(toast.success).mock.calls[0]
    expect(message).toContain('newer scan of this commit')
    expect(options?.description).toContain(NEWER_SCAN_ID)
  })

  it('links to the scan that took the mark', () => {
    markAndResolveTo(NEWER_SCAN_ID)

    const action = vi.mocked(toast.success).mock.calls[0][1]?.action
    expect(action).toMatchObject({ label: MARKED_SCAN_LINK })
  })

  it('closes the dialog once the mark is recorded', () => {
    markAndResolveTo(SCAN_ID)

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
