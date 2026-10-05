import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { toast } from 'sonner'

import { scanApi } from '@/api/scans'
import type { ProjectMember } from '@/types/project'
import type { SbomResponse, ScanAnalysisResult } from '@/types/scan'

import ScanDetails from '../ScanDetails'

const mockUseScan = vi.fn()
const mockMutate = vi.fn()
const releaseControlProps = vi.fn()
const { member } = vi.hoisted(() => ({ member: { current: undefined as ProjectMember | undefined } }))
const ALREADY_UNDER_WAY = 'A re-scan of this scan is already under way.'
const RESCAN_BUTTON = { name: /trigger re-scan/i }
const SCAN_PATH = '/projects/p1/scans/s1'
const RAW_TAB = `${SCAN_PATH}?tab=raw`
const SCANNER_ROW_ID = 's1:trivy:SBOM #1'

const TRIVY_RESULT = { Results: [{ Target: 'app.cdx.json', Vulnerabilities: [] }] }
const SBOM = { bomFormat: 'CycloneDX', specVersion: '1.6', components: [] }

// The rows GET /scans/{id}/results and /sboms answer: rows within and exactly at the preview limit, one byte over it, and lost files.
const RESULT_ROWS: ScanAnalysisResult[] = [
  { id: SCANNER_ROW_ID, scan_id: 's1', analyzer_name: 'trivy', source: 'SBOM #1', created_at: '2026-09-01T00:05:00Z', size: 2 * 1024 * 1024 },
  { id: 's1:epss_kev', scan_id: 's1', analyzer_name: 'epss_kev', source: null, created_at: '2026-09-01T00:06:00Z', size: 2 * 1024 * 1024 + 1 },
  { id: 's1:grype:SBOM #1', scan_id: 's1', analyzer_name: 'grype', source: 'SBOM #1', created_at: '2026-09-01T00:07:00Z', size: null },
]
const SBOM_ROWS: SbomResponse[] = [
  { index: 0, filename: 'app.cdx.json', size: 2048 },
  { index: 1, filename: null, size: null },
]

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

vi.mock('@/api/scans')
vi.mock('@/hooks/queries/use-scans', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/queries/use-scans')>()),
  useScan: (...args: unknown[]) => mockUseScan(...args),
  useScanHistory: () => ({ data: undefined }),
  useTriggerRescan: () => ({ mutate: mockMutate, isPending: false }),
  useScanStats: () => ({ data: undefined }),
}))

vi.mock('@/hooks/queries/use-projects', () => ({
  useProject: () => ({
    data: { id: 'p1', name: 'Proj', active_analyzers: [], members: [member.current] },
    isLoading: false,
  }),
}))

vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: [] }) }))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { id: 'u1' } }) }))

// The own member row as GET /projects/{id} returns it to a user who holds the project through a team.
function teamMember(effectiveRole: string): ProjectMember {
  return {
    user_id: 'u1', role: 'viewer', notification_preferences: {}, username: 'vui11viewer',
    inherited_from: 'Team: Team V-UI-11', effective_role: effectiveRole,
  }
}

vi.mock('@/components/findings/FindingsTable', () => ({ FindingsTable: () => null }))
vi.mock('@/components/findings/WaivedFindingsSection', () => ({ WaivedFindingsSection: () => null }))
vi.mock('@/components/scans/MarkReleaseButton', () => ({ MarkReleaseButton: () => <button>Mark as release</button> }))
vi.mock('@/components/scans/ScanReleaseControl', () => ({
  ScanReleaseControl: (props: unknown) => {
    releaseControlProps(props)
    return null
  },
}))

function scan(status: string) {
  return {
    id: 's1', project_id: 'p1', branch: 'main', status, created_at: '2026-09-01T00:00:00Z',
    sbom_refs: [{ type: 'gridfs_reference', gridfs_id: 'g1' }],
  }
}

function renderPage(entry = SCAN_PATH) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/projects/:projectId/scans/:scanId" element={<ScanDetails />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  member.current = teamMember('editor')
})

afterEach(cleanup)

describe('ScanDetails re-scan button', () => {
  it('tells the user why the server refused the re-scan', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    mockMutate.mockImplementation((_vars, options: { onError: (error: unknown) => void }) =>
      options.onError({ response: { status: 409, data: { detail: ALREADY_UNDER_WAY } } }),
    )

    renderPage()
    fireEvent.click(screen.getByRole('button', RESCAN_BUTTON))

    expect(toast.error).toHaveBeenCalledWith(expect.any(String), { description: ALREADY_UNDER_WAY })
  })

  it.each(['pending', 'processing'])('cannot be clicked while the scan is %s', (status) => {
    mockUseScan.mockReturnValue({ data: scan(status), isLoading: false })

    renderPage()

    expect(screen.getByRole('button', RESCAN_BUTTON)).toBeDisabled()
  })

  it('can be clicked once the scan is analysed', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })

    renderPage()

    expect(screen.getByRole('button', RESCAN_BUTTON)).toBeEnabled()
  })
})

describe('ScanDetails for a viewer', () => {
  beforeEach(() => {
    member.current = teamMember('viewer')
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
  })

  it('offers neither a re-scan nor a release mark, which the server refuses a viewer', () => {
    renderPage()

    expect(screen.queryByRole('button', RESCAN_BUTTON)).toBeNull()
    expect(screen.queryByRole('button', { name: 'Mark as release' })).toBeNull()
  })

  it('lets the release panel show the releases without the withdraw action', () => {
    renderPage()

    expect(releaseControlProps).toHaveBeenCalledWith(expect.objectContaining({ canWrite: false }))
  })
})

describe('ScanDetails for an editor', () => {
  it('offers the re-scan, the release mark and the withdraw action', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })

    renderPage()

    expect(screen.getByRole('button', RESCAN_BUTTON)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mark as release' })).toBeInTheDocument()
    expect(releaseControlProps).toHaveBeenCalledWith(expect.objectContaining({ canWrite: true }))
  })
})

describe('ScanDetails raw tab', () => {
  beforeEach(() => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    vi.mocked(scanApi.getResults).mockResolvedValue(RESULT_ROWS)
    vi.mocked(scanApi.getSboms).mockResolvedValue(SBOM_ROWS)
    vi.mocked(scanApi.downloadResult).mockResolvedValue({ blob: new Blob(['{}']), filename: null })
    vi.mocked(scanApi.downloadSbom).mockResolvedValue({ blob: new Blob(['{}']), filename: null })
    vi.mocked(scanApi.getResult).mockResolvedValue(TRIVY_RESULT)
    vi.mocked(scanApi.getSbom).mockResolvedValue(SBOM)
  })

  it('fetches neither list while another tab is open', () => {
    renderPage()

    expect(screen.getByRole('button', RESCAN_BUTTON)).toBeInTheDocument()
    expect(scanApi.getResults).not.toHaveBeenCalled()
    expect(scanApi.getSboms).not.toHaveBeenCalled()
  })

  it('fetches each list once when opened', async () => {
    renderPage(RAW_TAB)

    expect(await screen.findByText('app.cdx.json')).toBeInTheDocument()
    expect(scanApi.getResults).toHaveBeenCalledTimes(1)
    expect(scanApi.getSboms).toHaveBeenCalledTimes(1)
  })

  it('shows the stored size of a result row and an SBOM', async () => {
    renderPage(RAW_TAB)

    const result = await screen.findByRole('button', { name: 'Download trivy SBOM #1' })
    const sbom = await screen.findByRole('button', { name: 'Download app.cdx.json' })

    expect(within(result.parentElement!).getByText('2.0 MB')).toBeInTheDocument()
    expect(within(sbom.parentElement!).getByText('2.0 KB')).toBeInTheDocument()
  })

  it('downloads a result row and an SBOM through their own routes', async () => {
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'Download trivy SBOM #1' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Download app.cdx.json' }))

    expect(scanApi.downloadResult).toHaveBeenCalledWith('s1', SCANNER_ROW_ID)
    expect(scanApi.downloadSbom).toHaveBeenCalledWith('s1', 0)
  })

  it.each(['SBOM #2', 'grype SBOM #1'])('marks %s, whose stored file is gone, and offers neither preview nor download', async (label) => {
    renderPage(RAW_TAB)

    const download = await screen.findByRole('button', { name: `Download ${label}` })
    expect(download).toBeDisabled()
    expect(screen.getByRole('button', { name: `View ${label}` })).toBeDisabled()
    expect(within(download.parentElement!).getByText('Missing')).toBeInTheDocument()
  })

  it('fetches a result and an SBOM only when viewed and shows them pretty-printed', async () => {
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'View trivy SBOM #1' }))
    expect(scanApi.getSbom).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'View app.cdx.json' }))

    expect((await screen.findByText(/"Target"/)).textContent).toBe(JSON.stringify(TRIVY_RESULT, null, 2))
    expect((await screen.findByText(/"bomFormat"/)).textContent).toBe(JSON.stringify(SBOM, null, 2))
    expect(scanApi.getResult).toHaveBeenCalledWith('s1', SCANNER_ROW_ID)
    expect(scanApi.getSbom).toHaveBeenCalledWith('s1', 0)
  })

  it('offers no preview of a row over the limit and fetches nothing for it', async () => {
    renderPage(RAW_TAB)

    const view = await screen.findByRole('button', { name: 'View epss_kev' })
    fireEvent.click(view)

    expect(view).toBeDisabled()
    expect(view.parentElement).toHaveAttribute('title', 'Too large to preview, use Download')
    expect(screen.getByRole('button', { name: 'Download epss_kev' })).toBeEnabled()
    expect(scanApi.getResult).not.toHaveBeenCalled()
  })

  it('collapses a preview on Hide', async () => {
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'View app.cdx.json' }))
    await screen.findByText(/"bomFormat"/)
    fireEvent.click(screen.getByRole('button', { name: 'Hide app.cdx.json' }))

    expect(screen.queryByText(/"bomFormat"/)).toBeNull()
    expect(screen.getByRole('button', { name: 'View app.cdx.json' })).toBeEnabled()
  })

  it('says so when a preview cannot be loaded', async () => {
    vi.mocked(scanApi.getResult).mockRejectedValue(new Error('Request failed with status code 500'))
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'View trivy SBOM #1' }))

    expect(await screen.findByText('The file could not be loaded.')).toBeInTheDocument()
  })

  it('highlights the SBOM a deep link names', async () => {
    renderPage(`${RAW_TAB}&sbom=1`)

    const row = (await screen.findByRole('button', { name: 'Download SBOM #2' })).parentElement
    await waitFor(() => expect(row).toHaveClass('ring-2'))
  })
})
