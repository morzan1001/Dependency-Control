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
const CANARY = 'canary'
const VERSION_LIKE_ENVIRONMENT = '1-0-6'
const PRODUCTION_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const PRODUCTION_RELEASED_AT = '2026-09-01T10:00:00Z'
const MARK_BUTTON = 'Mark as release'
const ENVIRONMENT_FIELD = 'Environment to release to'
const VERSION_FIELD = 'Version'
const COMMIT_TAG = 'v2.0.0'
const NEXT_COMMIT_TAG = 'v2.1.0'
const TYPED_VERSION = '1.0.6'
const VERSION_LIKE_HINT = /looks like a version/i
const OFF_PATTERN_ENVIRONMENT = 'Pre-Prod!'
const OFF_PATTERN_HINT = /lowercase letters/i
const RESCAN_NOTE = /releases are held by the original scan/i
const ORIGINAL_SCAN_LINK = 'Open the original scan'

const mockMark = vi.fn()
const mockUnmark = vi.fn()
let mockProjectEnvironments: string[] | undefined

vi.mock('@/hooks/queries/use-releases', () => ({
  useMarkRelease: () => ({ mutate: mockMark, isPending: false }),
  useUnmarkRelease: () => ({ mutate: mockUnmark, isPending: false }),
  useReleaseEnvironments: () => ({ data: mockProjectEnvironments }),
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
function markResponse(scanId: string, version: string | null): ReleaseItem {
  return {
    scan_id: scanId,
    project_id: PROJECT_ID,
    environment: PRODUCTION,
    version,
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

function markAndResolveTo(scanId: string, version: string | null = null) {
  const dialog = openDialog(makeScan())
  fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))
  const handlers = mockMark.mock.calls[0][1] as { onSuccess: (release: ReleaseItem) => void }
  // Resolving outside React's event system: act() flushes the close that onSuccess triggers.
  act(() => handlers.onSuccess(markResponse(scanId, version)))
}

function suggestionsIn(dialog: ReturnType<typeof within>): string[] {
  const listId = dialog.getByLabelText(ENVIRONMENT_FIELD).getAttribute('list') ?? ''
  return Array.from(document.getElementById(listId)?.querySelectorAll('option') ?? [], (option) => option.value)
}

function markWithVersion(scan: ScanWithReleases, typed: string) {
  const dialog = openDialog(scan)
  fireEvent.change(dialog.getByLabelText(VERSION_FIELD), { target: { value: typed } })
  fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))
  return mockMark.mock.calls[0][0].payload
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectEnvironments = undefined
})

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

  it('names the version the release was recorded under', () => {
    // No version was typed: the backend's fallback named it, and the toast says what it stored.
    markAndResolveTo(SCAN_ID, PRODUCTION_VERSION)

    expect(toast.success).toHaveBeenCalledWith(`Marked as release ${PRODUCTION_VERSION} in ${PRODUCTION}`)
  })

  it('opens with the default as a placeholder, so the browser lists every suggestion unfiltered', () => {
    const dialog = openDialog(makeScan())

    expect(dialog.getByLabelText(ENVIRONMENT_FIELD)).toHaveValue('')
    expect(dialog.getByLabelText(ENVIRONMENT_FIELD)).toHaveAttribute('placeholder', PRODUCTION)
  })

  it('suggests the default and every environment the project released to, each once', () => {
    mockProjectEnvironments = [CANARY, PRODUCTION, STAGING]

    const dialog = openDialog(makeScan())

    expect(suggestionsIn(dialog)).toEqual([PRODUCTION, CANARY, STAGING])
  })

  it('suggests the default before the project has released anywhere', () => {
    const dialog = openDialog(makeScan())

    expect(suggestionsIn(dialog)).toEqual([PRODUCTION])
  })

  it('does not suggest an environment that looks like a version', () => {
    mockProjectEnvironments = [VERSION_LIKE_ENVIRONMENT, STAGING]

    const dialog = openDialog(makeScan())

    expect(suggestionsIn(dialog)).toEqual([PRODUCTION, STAGING])
  })

  it("prefills the version with the scan's tag and sends it", () => {
    const dialog = openDialog(makeScan({ commit_tag: COMMIT_TAG }))

    expect(dialog.getByLabelText(VERSION_FIELD)).toHaveValue(COMMIT_TAG)
    fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))
    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH, environment: PRODUCTION, version: COMMIT_TAG } },
      expect.anything(),
    )
  })

  it('prefills the tag of the scan on screen after the page swapped scans', () => {
    const { rerender } = renderButton(makeScan({ commit_tag: COMMIT_TAG }))
    rerender(
      <MemoryRouter>
        <MarkReleaseButton projectId={PROJECT_ID} scan={makeScan({ id: NEWER_SCAN_ID, commit_tag: NEXT_COMMIT_TAG })} />
      </MemoryRouter>,
    )

    fireEvent.click(screen.getByRole('button', { name: MARK_BUTTON }))

    expect(within(screen.getByRole('dialog')).getByLabelText(VERSION_FIELD)).toHaveValue(NEXT_COMMIT_TAG)
  })

  it('sends a typed version without the whitespace around it', () => {
    expect(markWithVersion(makeScan(), `  ${TYPED_VERSION}  `)).toEqual({
      commit_hash: COMMIT_HASH,
      environment: PRODUCTION,
      version: TYPED_VERSION,
    })
  })

  it('leaves a cleared version out, so the backend falls back to the tag', () => {
    expect(markWithVersion(makeScan({ commit_tag: COMMIT_TAG }), '   ')).not.toHaveProperty('version')
  })

  it.each(['1.0.6', VERSION_LIKE_ENVIRONMENT, 'v2.3', '1_0_6'])('warns that %s looks like a version', (typed) => {
    const dialog = openDialog(makeScan())

    fireEvent.change(dialog.getByLabelText(ENVIRONMENT_FIELD), { target: { value: typed } })

    expect(dialog.getByText(VERSION_LIKE_HINT)).toBeInTheDocument()
  })

  it.each([PRODUCTION, 'eu-1', 'prod2', 'stage-2'])('does not take %s for a version', (typed) => {
    const dialog = openDialog(makeScan())

    fireEvent.change(dialog.getByLabelText(ENVIRONMENT_FIELD), { target: { value: typed } })

    expect(dialog.queryByText(VERSION_LIKE_HINT)).not.toBeInTheDocument()
  })

  it('still marks into an environment that looks like a version', () => {
    const dialog = openDialog(makeScan())

    fireEvent.change(dialog.getByLabelText(ENVIRONMENT_FIELD), { target: { value: VERSION_LIKE_ENVIRONMENT } })
    fireEvent.click(dialog.getByRole('button', { name: MARK_BUTTON }))

    expect(mockMark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH, environment: VERSION_LIKE_ENVIRONMENT } },
      expect.anything(),
    )
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
