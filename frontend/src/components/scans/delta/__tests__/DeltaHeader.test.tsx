// Force a non-UTC timezone so date parsing is exercised in local time.
process.env.TZ = 'America/New_York'

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { DeltaHeader } from '../DeltaHeader'
import * as scansApi from '@/api/scans'
import { useLatestProjectRelease, type LatestProjectRelease } from '@/hooks/queries/use-releases'
import { SCAN_WINDOW_PAGE_SIZE, useProjectScanWindow, type ScanWindow } from '@/hooks/queries/use-scans'
import type { ReleaseItem } from '@/types/release'
import type { ScanWithReleases } from '@/types/scan'
import type { ScanDeltaResponse } from '@/types/scanDelta'

vi.mock('@/api/scans')
vi.mock('@/hooks/queries/use-scans')
vi.mock('@/hooks/queries/use-releases')

const PROJECT_ID = 'p1'
const PRODUCTION = 'production'
const STAGING = 'staging'
const RELEASE_VERSION = 'v1.2.3'
const RELEASE_SCAN_ID = 'rel-outside-window'
const RELEASE_RESCAN_ID = 'rel-rescan'
const COMMIT_HASH = 'a'.repeat(40)
const QUICK_PICK_LABEL = `Latest ${PRODUCTION} release`
const STAGING_QUICK_PICK_LABEL = `Latest ${STAGING} release`
const ANY_QUICK_PICK_LABEL = /^Latest .+ release$/
const RELEASE_MARKER_LABEL = 'Release'

// 'rescan-1' is a rescan the project-scans hook excludes from its option list.
// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
const rescan: ScanWithReleases = { id: 'rescan-1', project_id: PROJECT_ID, branch: 'feature-x', status: 'completed', created_at: '2026-08-10T12:00:00Z', releases: [] }
const toScan: ScanWithReleases = { id: 'b', project_id: PROJECT_ID, branch: 'main', status: 'completed', created_at: '2026-08-09T12:00:00Z', releases: [] }
const releasedOption: ScanWithReleases = { id: 'released-option', project_id: PROJECT_ID, branch: 'main', status: 'completed', created_at: '2026-08-08T12:00:00Z', is_release: true, releases: [] }

const release: ReleaseItem = {
  scan_id: RELEASE_SCAN_ID,
  project_id: PROJECT_ID,
  environment: PRODUCTION,
  version: RELEASE_VERSION,
  commit_hash: COMMIT_HASH,
  branch: 'main',
  released_at: '2026-01-01T00:00:00Z',
  scan_status: 'completed',
  analysis_scan_id: RELEASE_SCAN_ID,
  analysis_chain_bounded: false,
}

function getOne(id: string): Promise<ScanWithReleases> {
  const known = [rescan, toScan, releasedOption].find((scan) => scan.id === id)
  if (known) return Promise.resolve(known)
  return Promise.reject(new Error(`unexpected scan id ${id}`))
}

function renderHeader(
  onChange = vi.fn(),
  releases: ReleaseItem[] = [],
  toScanId: string = toScan.id,
  delta: ScanDeltaResponse | null = null,
) {
  // Annotated, not inferred: an inferred fixture drops a field from the hook's type silently.
  const resolved: LatestProjectRelease = {
    latestRelease: releases[0],
    hasReleases: releases.length > 0,
    isLoading: false,
  }
  vi.mocked(useLatestProjectRelease).mockReturnValue(resolved)
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <DeltaHeader projectId={PROJECT_ID} fromScanId={rescan.id} toScanId={toScanId} onChange={onChange}
        delta={delta} />
    </QueryClientProvider>,
  )
  return { onChange }
}

function mockScanSources(options: ScanWithReleases[] = [toScan], complete = true) {
  vi.mocked(scansApi.scanApi.getOne).mockImplementation(getOne)
  // Annotated, not inferred: an inferred fixture drops a field from the hook's type silently.
  const window: ScanWindow = { scans: options, complete }
  vi.mocked(useProjectScanWindow).mockReturnValue(
    { data: window } as unknown as ReturnType<typeof useProjectScanWindow>,
  )
}

describe('DeltaHeader', () => {
  afterEach(() => vi.clearAllMocks())

  it('says the pickers are a window and offers to widen it when older scans exist', () => {
    mockScanSources([toScan, releasedOption], false)

    renderHeader()

    expect(screen.getByText(/this project has older ones/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: `Load ${SCAN_WINDOW_PAGE_SIZE} older` })).toBeInTheDocument()
  })

  it('claims nothing about older scans once the window read to the end', () => {
    mockScanSources([toScan, releasedOption], true)

    renderHeader()

    expect(screen.queryByText(/this project has older ones/)).not.toBeInTheDocument()
  })

  it('asks the window for another page when the widen control is used', () => {
    mockScanSources([toScan], false)

    renderHeader()
    fireEvent.click(screen.getByRole('button', { name: `Load ${SCAN_WINDOW_PAGE_SIZE} older` }))

    const pagesAsked = vi.mocked(useProjectScanWindow).mock.calls.map((call) => call[1])
    expect(Math.max(...pagesAsked)).toBe(2)
  })

  it("shows the compared scan's label on the From side even though it is excluded from the pickable options", async () => {
    mockScanSources()

    renderHeader()

    const [fromTrigger] = screen.getAllByRole('combobox')
    await waitFor(() => expect(fromTrigger).toHaveTextContent(/feature-x/))
  })

  it('swaps the pair when the swap button is clicked', () => {
    mockScanSources()

    const { onChange } = renderHeader()

    fireEvent.click(screen.getByLabelText('Swap scans'))

    expect(onChange).toHaveBeenCalledWith(toScan.id, rescan.id)
  })

  it('marks a released scan with an icon rather than a word, because the trigger width is fixed', async () => {
    mockScanSources([toScan, releasedOption])

    renderHeader(vi.fn(), [], releasedOption.id)

    await waitFor(() => expect(screen.getByLabelText(RELEASE_MARKER_LABEL)).toBeInTheDocument())
  })
})

describe('DeltaHeader - release quick pick', () => {
  afterEach(() => vi.clearAllMocks())

  it('is hidden when the project has no release', () => {
    mockScanSources()

    renderHeader()

    expect(screen.queryByRole('button', { name: ANY_QUICK_PICK_LABEL })).not.toBeInTheDocument()
  })

  // An unqualified fetch returns the newest release of any environment, so a project that deploys
  // to staging on every merge would otherwise offer a staging scan under a production-sounding name.
  it('names the environment it resolved, which need not be production', () => {
    mockScanSources()

    renderHeader(vi.fn(), [{ ...release, environment: STAGING }])

    expect(screen.getByRole('button', { name: STAGING_QUICK_PICK_LABEL })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: QUICK_PICK_LABEL })).not.toBeInTheDocument()
  })

  it('compares the release against the current To side', () => {
    mockScanSources()

    const { onChange } = renderHeader(vi.fn(), [release])

    fireEvent.click(screen.getByRole('button', { name: QUICK_PICK_LABEL }))

    expect(onChange).toHaveBeenCalledWith(RELEASE_SCAN_ID, toScan.id)
  })

  it('says nothing about releases on a project that reports none, rather than hinting at a fault', () => {
    mockScanSources()

    renderHeader()

    expect(screen.queryByText(/release/i)).not.toBeInTheDocument()
  })
})

describe('DeltaHeader - what the comparison actually used', () => {
  const RESOLVED_FROM_ID = 'resolved-from'
  const RESOLVED_TO_ID = 'resolved-to'
  const RESOLVED_FROM_BRANCH = 'release-1.0'
  const RESOLVED_TO_BRANCH = 'main'
  const RESOLVED_FROM_COMMIT = 'b'.repeat(40)
  const SHORT_FROM_COMMIT = RESOLVED_FROM_COMMIT.slice(0, 7)
  const FIRST_PAGE = 1
  const PAGE_SIZE = 50
  const ONE_PAGE = 1
  const NONE = 0

  // Annotated, not inferred: an inferred fixture drops a field from the response type silently.
  function deltaWithSides(): ScanDeltaResponse {
    return {
      category: 'findings',
      from_scan_id: rescan.id,
      to_scan_id: toScan.id,
      from_side: {
        scan_id: RESOLVED_FROM_ID,
        branch: RESOLVED_FROM_BRANCH,
        commit_hash: RESOLVED_FROM_COMMIT,
        created_at: '2026-01-02T03:04:00Z',
      },
      to_side: {
        scan_id: RESOLVED_TO_ID,
        branch: RESOLVED_TO_BRANCH,
        commit_hash: null,
        created_at: null,
      },
      project_id: PROJECT_ID,
      totals: { added: NONE, removed: NONE, unchanged: NONE, changed: NONE, by_severity: {}, by_type: {} },
      page: FIRST_PAGE,
      page_size: PAGE_SIZE,
      total_pages: ONE_PAGE,
      items: [],
      from_waived_excluded: NONE,
      to_waived_excluded: NONE,
      waiver_only_changes: NONE,
    }
  }

  afterEach(() => vi.clearAllMocks())

  it('names the build each side resolved to, so a wrong side is visible rather than inferred', () => {
    mockScanSources()

    renderHeader(vi.fn(), [], toScan.id, deltaWithSides())

    expect(screen.getByTitle(RESOLVED_FROM_ID)).toBeInTheDocument()
    expect(screen.getByTitle(RESOLVED_TO_ID)).toBeInTheDocument()
  })

  it('describes each side with the branch, commit and time the response reports', () => {
    mockScanSources()

    renderHeader(vi.fn(), [], toScan.id, deltaWithSides())

    expect(screen.getByText(RESOLVED_FROM_BRANCH)).toBeInTheDocument()
    expect(screen.getByText(SHORT_FROM_COMMIT)).toBeInTheDocument()
    expect(screen.getByText(RESOLVED_TO_BRANCH)).toBeInTheDocument()
  })

  it('falls back to the requested scan before the first response lands', async () => {
    mockScanSources()

    renderHeader()

    await waitFor(() => expect(screen.getByText(rescan.branch)).toBeInTheDocument())
    expect(screen.queryByTitle(RESOLVED_FROM_ID)).not.toBeInTheDocument()
  })

  it('names the environment and version the quick pick would compare against', () => {
    mockScanSources()

    renderHeader(vi.fn(), [release])

    expect(
      screen.getByText(`Compares the ${PRODUCTION} release ${RELEASE_VERSION} against the To scan.`),
    ).toBeInTheDocument()
  })

  it('does not offer a release that is already one side of the comparison', () => {
    mockScanSources()

    const { onChange } = renderHeader(
      vi.fn(),
      [{ ...release, scan_id: toScan.id, analysis_scan_id: toScan.id }],
    )

    fireEvent.click(screen.getByRole('button', { name: QUICK_PICK_LABEL }))

    expect(onChange).not.toHaveBeenCalled()
    expect(screen.getByText(`Already comparing the ${PRODUCTION} release.`)).toBeInTheDocument()
  })

  it('picks the scan the rescan chain resolved, the one the backend reports the release as', () => {
    mockScanSources()

    const { onChange } = renderHeader(vi.fn(), [{ ...release, analysis_scan_id: RELEASE_RESCAN_ID }])

    fireEvent.click(screen.getByRole('button', { name: QUICK_PICK_LABEL }))

    expect(onChange).toHaveBeenCalledWith(RELEASE_RESCAN_ID, toScan.id)
  })

  it('says so rather than offering a release whose chain holds no readable scan', () => {
    mockScanSources()

    renderHeader(vi.fn(), [{ ...release, scan_status: null, analysis_scan_id: null }])

    expect(screen.queryByRole('button', { name: QUICK_PICK_LABEL })).not.toBeInTheDocument()
    expect(
      screen.getByText(`The ${PRODUCTION} release has no readable scan to compare.`),
    ).toBeInTheDocument()
  })
})
