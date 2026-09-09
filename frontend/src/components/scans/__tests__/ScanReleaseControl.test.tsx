import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { toast } from 'sonner'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ScanReleaseControl } from '../ScanReleaseControl'
import { formatDateTime } from '@/lib/utils'
import type { ReleaseItem, UnmarkReleaseResponse } from '@/types/release'
import type { ScanReleaseRef, ScanWithReleases } from '@/types/scan'

const PROJECT_ID = 'p1'
const SCAN_ID = 'scan-1'
const ORIGINAL_SCAN_ID = 'scan-0'
const COMMIT_HASH = 'a'.repeat(40)
const PRODUCTION = 'production'
const STAGING = 'staging'
const PRODUCTION_VERSION = 'v1.2.3'
const STAGING_VERSION = 'v1.3.0-rc1'
const PRODUCTION_RELEASED_AT = '2026-09-01T10:00:00Z'
const STAGING_RELEASED_AT = '2026-09-02T11:00:00Z'
const GENERIC_RELEASE_LABEL = 'Release'
const UNCOVERED_SCAN_ID = 'scan-old'
const UNCOVERED_VERSION = 'v0.9.0'
const UNCOVERED_RELEASED_AT = '2026-08-05T16:49:16Z'
const NO_ENVIRONMENTS: string[] = []

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

function renderControl(scan: ScanWithReleases) {
  return render(
    <MemoryRouter>
      <ScanReleaseControl projectId={PROJECT_ID} scan={scan} />
    </MemoryRouter>,
  )
}

beforeEach(() => vi.clearAllMocks())

describe('ScanReleaseControl', () => {
  it('withdraws the environment whose button was pressed', () => {
    const scan = releasedScan([
      makeRelease({ environment: STAGING, version: STAGING_VERSION, released_at: STAGING_RELEASED_AT }),
      makeRelease(),
    ])
    renderControl(scan)

    expect(screen.getByLabelText(`Release ${STAGING_VERSION} in ${STAGING}`)).toBeInTheDocument()
    expect(screen.getByLabelText(`Release ${PRODUCTION_VERSION} in ${PRODUCTION}`)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: `Withdraw from ${STAGING}` }))

    expect(mockUnmark).toHaveBeenCalledWith(
      { projectId: PROJECT_ID, scanId: SCAN_ID, environment: STAGING },
      expect.anything(),
    )
  })

  // Annotated, not inferred: an inferred fixture drops a field from the response type silently.
  function unmarkResponse(uncovered: ReleaseItem | null): UnmarkReleaseResponse {
    return {
      scan_id: SCAN_ID,
      environment: PRODUCTION,
      is_release: false,
      remaining_environments: NO_ENVIRONMENTS,
      environment_release: uncovered,
    }
  }

  function withdrawAndResolveTo(uncovered: ReleaseItem | null) {
    fireEvent.click(screen.getByRole('button', { name: `Withdraw from ${PRODUCTION}` }))
    const handlers = mockUnmark.mock.calls[0][1] as { onSuccess: (r: UnmarkReleaseResponse) => void }
    handlers.onSuccess(unmarkResponse(uncovered))
  }

  it('says which release the withdrawal uncovered rather than reporting a plain success', () => {
    renderControl(releasedScan([makeRelease()]))

    withdrawAndResolveTo({
      ...markResponse(UNCOVERED_SCAN_ID),
      version: UNCOVERED_VERSION,
      released_at: UNCOVERED_RELEASED_AT,
    })

    expect(toast.warning).toHaveBeenCalledWith(
      expect.stringContaining(`Withdrawn from ${PRODUCTION}`),
      expect.objectContaining({
        description: expect.stringContaining(UNCOVERED_VERSION),
      }),
    )
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('confirms plainly when the environment is left with nothing deployed', () => {
    renderControl(releasedScan([makeRelease()]))

    withdrawAndResolveTo(null)

    expect(toast.success).toHaveBeenCalledWith(`Withdrawn from ${PRODUCTION}`)
    expect(toast.warning).not.toHaveBeenCalled()
  })

  it('names when each environment took the release', () => {
    const scan = releasedScan([
      makeRelease({ environment: STAGING, released_at: STAGING_RELEASED_AT }),
      makeRelease(),
    ])
    renderControl(scan)

    expect(screen.getByText(`Released ${formatDateTime(STAGING_RELEASED_AT)}`)).toBeInTheDocument()
    expect(screen.getByText(`Released ${formatDateTime(PRODUCTION_RELEASED_AT)}`)).toBeInTheDocument()
  })

  it('keeps the badge for a release whose record it cannot see', () => {
    renderControl(releasedScan([]))

    expect(screen.getByLabelText(GENERIC_RELEASE_LABEL)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Withdraw from/ })).not.toBeInTheDocument()
  })

  it('renders nothing at all for a scan that is not a release', () => {
    const { container } = renderControl(makeScan())

    // The panel used to occupy the metadata card with an input and a button on every scan.
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing for a re-scan, whose releases belong to the original scan', () => {
    const { container } = renderControl(makeScan({ is_rescan: true, original_scan_id: ORIGINAL_SCAN_ID }))

    expect(container).toBeEmptyDOMElement()
  })
})
