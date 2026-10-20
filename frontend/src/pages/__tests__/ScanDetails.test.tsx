import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cloneElement, type ReactElement } from 'react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { toast } from 'sonner'

import { projectApi } from '@/api/projects'
import { scanApi } from '@/api/scans'
import { SEVERITY_CHART_COLORS } from '@/lib/finding-utils'
import { createMutationCache } from '@/lib/mutation-cache'
import type { ProjectMember } from '@/types/project'
import type { SbomResponse, ScanAnalysisResult } from '@/types/scan'

import ScanDetails from '../ScanDetails'

const mockUseScan = vi.fn()
const releaseControlProps = vi.fn()
const findingsTableProps = vi.fn()
const waivedSectionProps = vi.fn()
const { member, auth, analyzers, categories } = vi.hoisted(() => ({
  member: { current: undefined as ProjectMember | undefined },
  auth: { permissions: [] as string[] },
  analyzers: { active: [] as string[] },
  categories: { stats: undefined as Record<string, number> | undefined },
}))
const ALREADY_UNDER_WAY = 'A re-scan of this scan is already under way'
const RESCAN_BUTTON = { name: /trigger re-scan/i }
const SCAN_PATH = '/projects/p1/scans/s1'
const RAW_TAB = `${SCAN_PATH}?tab=raw`
const SCANNER_ROW_ID = 's1:trivy:SBOM #1'

const TRIVY_RESULT = { Results: [{ Target: 'app.cdx.json', Vulnerabilities: [] }] }
const SBOM = { bomFormat: 'CycloneDX', specVersion: '1.6', components: [] }

// Rows within and at the preview limit, one byte over it, and lost files, as the results endpoints answer.
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
  useScanStats: () => ({ data: categories.stats }),
}))

vi.mock('recharts', async (importOriginal) => {
  const recharts = await importOriginal<typeof import('recharts')>()
  return {
    ...recharts,
    // jsdom lays nothing out, so the chart gets the size a browser would measure.
    ResponsiveContainer: ({ children }: { children: ReactElement<{ width?: number; height?: number }> }) =>
      cloneElement(children, { width: 400, height: 300 }),
  }
})

vi.mock('@/hooks/queries/use-projects', () => ({
  useProject: () => ({
    data: { id: 'p1', name: 'Proj', active_analyzers: analyzers.active, members: [member.current] },
    isLoading: false,
  }),
}))

vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: auth.permissions }) }))
vi.mock('@/api/projects', () => ({ projectApi: { unpinScan: vi.fn().mockResolvedValue({ scan_id: 's1', pinned: false }) } }))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { id: 'u1' } }) }))

// The own member row as GET /projects/{id} returns it to a user who holds the project through a team.
function teamMember(effectiveRole: string): ProjectMember {
  return {
    user_id: 'u1', role: 'viewer', notification_preferences: {}, username: 'vui11viewer',
    inherited_from: 'Team: Team V-UI-11', effective_role: effectiveRole,
  }
}

vi.mock('@/components/findings/FindingsTable', () => ({
  FindingsTable: (props: unknown) => {
    findingsTableProps(props)
    return null
  },
}))
vi.mock('@/components/findings/WaivedFindingsSection', () => ({
  WaivedFindingsSection: (props: unknown) => {
    waivedSectionProps(props)
    return null
  },
}))
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
  const queryClient = new QueryClient({ mutationCache: createMutationCache(), defaultOptions: { queries: { retry: false } } })
  const router = createMemoryRouter(
    [{ path: '/projects/:projectId/scans/:scanId', element: <ScanDetails /> }],
    { initialEntries: [entry] },
  )
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return router
}

beforeEach(() => {
  vi.clearAllMocks()
  member.current = teamMember('editor')
  auth.permissions = []
  analyzers.active = []
  categories.stats = undefined
})

afterEach(cleanup)

describe('ScanDetails header', () => {
  it('stacks its actions under the title on a phone and wraps them, like the project page header', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })

    renderPage()

    const actions = screen.getByRole('button', RESCAN_BUTTON).parentElement!
    expect(actions).toHaveClass('flex-wrap')
    expect(actions.parentElement).toHaveClass('flex-col', 'sm:flex-row', 'sm:items-center', 'sm:justify-between')
  })
})

describe('ScanDetails re-scan button', () => {
  it('tells the user why the server refused the re-scan', async () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    vi.mocked(scanApi.triggerRescan).mockRejectedValue({ response: { status: 409, data: { detail: ALREADY_UNDER_WAY } } })

    renderPage()
    fireEvent.click(screen.getByRole('button', RESCAN_BUTTON))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to trigger re-scan', { description: ALREADY_UNDER_WAY }))
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

describe('ScanDetails severity link', () => {
  beforeEach(() => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
  })

  it('names the severity the findings are filtered by and lifts the filter on request', () => {
    const router = renderPage(`${SCAN_PATH}?severity=CRITICAL`)

    fireEvent.click(screen.getByRole('button', { name: /Severity: CRITICAL/ }))

    expect(new URLSearchParams(router.state.location.search).has('severity')).toBe(false)
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

  it('names a failed result and SBOM download and why, like the app\'s other failures', async () => {
    vi.mocked(scanApi.downloadResult).mockRejectedValue(new Error('Network Error'))
    vi.mocked(scanApi.downloadSbom).mockRejectedValue(new Error('Network Error'))
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'Download trivy SBOM #1' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Download app.cdx.json' }))

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Failed to download analyzer result', { description: 'Network Error' })
      expect(toast.error).toHaveBeenCalledWith('Failed to download SBOM', { description: 'Network Error' })
    })
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

  it('shows a skeleton until the preview has loaded', async () => {
    let resolve!: (data: unknown) => void
    vi.mocked(scanApi.getResult).mockReturnValue(new Promise((r) => { resolve = r }))
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'View trivy SBOM #1' }))
    const row = screen.getByRole('button', { name: 'Hide trivy SBOM #1' }).closest('.flex-wrap')!
    expect(row.querySelector('.animate-pulse')).not.toBeNull()
    expect(row.querySelector('pre')).toBeNull()
    resolve(TRIVY_RESULT)

    await screen.findByText(/"Target"/)
    expect(row.querySelector('.animate-pulse')).toBeNull()
  })

  it('previews each SBOM by its own index', async () => {
    vi.mocked(scanApi.getSboms).mockResolvedValue([
      { index: 0, filename: 'app.cdx.json', size: 2048 },
      { index: 1, filename: 'lib.cdx.json', size: 1024 },
    ])
    vi.mocked(scanApi.getSbom).mockImplementation(async (_scanId, index) => ({ serialNumber: `urn:uuid:${index}` }))
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'View app.cdx.json' }))
    await screen.findByText(/urn:uuid:0/)
    fireEvent.click(screen.getByRole('button', { name: 'View lib.cdx.json' }))

    expect(await screen.findByText(/urn:uuid:1/)).toBeInTheDocument()
    expect(scanApi.getSbom).toHaveBeenCalledWith('s1', 1)
  })

  it('copies the pretty-printed file', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    renderPage(RAW_TAB)

    fireEvent.click(await screen.findByRole('button', { name: 'View app.cdx.json' }))
    const code = await screen.findByText(/"bomFormat"/)
    fireEvent.click(within(code.parentElement!).getByRole('button', { name: 'Copy' }))

    expect(writeText).toHaveBeenCalledWith(JSON.stringify(SBOM, null, 2))
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

  it('closes an open preview when the page moves to another scan', async () => {
    vi.mocked(scanApi.getSboms).mockImplementation(async (scanId) => [
      scanId === 's1' ? SBOM_ROWS[0] : { index: 0, filename: 'huge.cdx.json', size: 500 * 1024 * 1024 },
    ])
    const router = renderPage('/projects/p1/scans/s2?tab=raw')
    await screen.findByRole('button', { name: 'View huge.cdx.json' })
    await act(() => router.navigate(RAW_TAB))
    fireEvent.click(await screen.findByRole('button', { name: 'View app.cdx.json' }))
    await screen.findByText(/"bomFormat"/)

    await act(() => router.navigate(-1))

    expect(await screen.findByRole('button', { name: 'View huge.cdx.json' })).toBeDisabled()
    expect(scanApi.getSbom).not.toHaveBeenCalledWith('s2', 0)
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

  it('highlights the only SBOM of a scan for a named Found In source', async () => {
    vi.mocked(scanApi.getSboms).mockResolvedValue([SBOM_ROWS[0]])
    renderPage(`${RAW_TAB}&sbomSource=my-service`)

    const row = (await screen.findByRole('button', { name: 'Download app.cdx.json' })).parentElement
    await waitFor(() => expect(row).toHaveClass('ring-2'))
  })

  it('highlights no SBOM of a multi-SBOM scan for a named Found In source', async () => {
    renderPage(`${RAW_TAB}&sbomSource=my-service`)

    const first = (await screen.findByRole('button', { name: 'Download app.cdx.json' })).parentElement
    const second = screen.getByRole('button', { name: 'Download SBOM #2' }).parentElement
    await act(() => new Promise((resolve) => setTimeout(resolve, 300)))
    expect(first).not.toHaveClass('ring-2')
    expect(second).not.toHaveClass('ring-2')
  })
})

describe('ScanDetails for a scan pinned by an archive restore', () => {
  const UNPIN_BUTTON = { name: /unpin/i }
  const pinned = () => ({ ...scan('completed'), pinned: true })

  beforeEach(() => {
    member.current = teamMember('admin')
    auth.permissions = ['archive:restore']
  })

  it('lets a project admin unpin it so retention can process it again', async () => {
    mockUseScan.mockReturnValue({ data: pinned(), isLoading: false })

    renderPage()
    fireEvent.click(screen.getByRole('button', UNPIN_BUTTON))

    await waitFor(() => expect(projectApi.unpinScan).toHaveBeenCalledWith('p1', 's1'))
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
  })

  it('names an unpin that failed and why', async () => {
    vi.mocked(projectApi.unpinScan).mockRejectedValueOnce(new Error('Network Error'))
    mockUseScan.mockReturnValue({ data: pinned(), isLoading: false })

    renderPage()
    fireEvent.click(screen.getByRole('button', UNPIN_BUTTON))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to unpin scan', { description: 'Network Error' }))
  })

  it('offers no unpin for a scan that is not pinned', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })

    renderPage()

    expect(screen.queryByRole('button', UNPIN_BUTTON)).not.toBeInTheDocument()
  })

  it('offers no unpin to a project editor, whom the server refuses', () => {
    member.current = teamMember('editor')
    mockUseScan.mockReturnValue({ data: pinned(), isLoading: false })

    renderPage()

    expect(screen.queryByRole('button', UNPIN_BUTTON)).not.toBeInTheDocument()
  })

  it('offers no unpin without archive:restore', () => {
    auth.permissions = []
    mockUseScan.mockReturnValue({ data: pinned(), isLoading: false })

    renderPage()

    expect(screen.queryByRole('button', UNPIN_BUTTON)).not.toBeInTheDocument()
  })
})

describe('ScanDetails source links', () => {
  const GITLAB = 'https://gitlab.example.com/acme/widget'
  const COMMIT = 'abcdef1234567890abcdef1234567890abcdef12'

  it('links branch, commit and pipeline to the SCM in a new tab', () => {
    mockUseScan.mockReturnValue({
      data: { ...scan('completed'), project_url: GITLAB, pipeline_id: 9001, commit_hash: COMMIT },
      isLoading: false,
    })
    renderPage()

    expect(screen.getByRole('link', { name: 'main' })).toHaveAttribute('href', `${GITLAB}/-/tree/main`)
    expect(screen.getByRole('link', { name: 'abcdef1' })).toHaveAttribute('href', `${GITLAB}/-/commit/${COMMIT}`)
    expect(screen.getByRole('link', { name: '#9001' })).toHaveAttribute('href', `${GITLAB}/-/pipelines/9001`)
    for (const name of ['main', 'abcdef1', '#9001']) {
      expect(screen.getByRole('link', { name })).toHaveAttribute('target', '_blank')
    }
  })

  it('shows branch and commit as text and no pipeline when the SCM is unknown', () => {
    mockUseScan.mockReturnValue({
      data: { ...scan('completed'), pipeline_id: 9001, commit_hash: COMMIT },
      isLoading: false,
    })
    renderPage()

    expect(screen.queryByRole('link', { name: 'main' })).toBeNull()
    expect(screen.getByText('abcdef1')).toBeInTheDocument()
    expect(screen.queryByText('#9001')).toBeNull()
  })
})


const tabNames = () => screen.getAllByRole('tab').map((tab) => tab.textContent)
const lastProps = (mock: typeof findingsTableProps) => mock.mock.lastCall?.[0] as Record<string, unknown>

describe('ScanDetails finding tabs', () => {
  beforeEach(() => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
  })

  it.each([
    [[], []],
    [['trivy'], ['Security', 'Compliance']],
    [['grype'], ['Security']],
    [['osv'], ['Security']],
    [['deps_dev'], ['Security']],
    [['os_malware'], ['Security']],
    [['typosquatting'], ['Security']],
    [['hash_verification'], ['Security']],
    [['trufflehog'], ['Secrets']],
    [['opengrep'], ['SAST']],
    [['kics'], ['SAST']],
    [['bearer'], ['SAST']],
    [['license_compliance'], ['Compliance']],
    [['end_of_life'], ['Compliance']],
    [['outdated_packages'], ['Quality']],
    [['maintainer_risk'], ['Quality']],
    [['epss_kev', 'reachability'], []],
    [['cbomkit'], []],
    [['maintainer_risk', 'trufflehog', 'osv', 'kics', 'end_of_life'], ['Security', 'Secrets', 'SAST', 'Compliance', 'Quality']],
  ])('shows the tabs of the analyzers %j next to All Findings and Raw Data', (active, tabs) => {
    analyzers.active = active
    renderPage()

    expect(tabNames()).toEqual(['All Findings', ...tabs, 'Raw Data'])
  })

  it.each([
    ['overview', undefined],
    ['security', 'security'],
    ['secrets', 'secret'],
    ['sast', 'sast'],
    ['compliance', 'compliance'],
    ['quality', 'quality'],
  ])('lists the %s tab\'s findings and waived findings by category %s', (tab, category) => {
    analyzers.active = ['osv', 'trufflehog', 'opengrep', 'license_compliance', 'outdated_packages']
    renderPage(`${SCAN_PATH}?tab=${tab}`)

    expect(lastProps(findingsTableProps)).toMatchObject({ scanId: 's1', projectId: 'p1' })
    expect(lastProps(findingsTableProps).category).toBe(category)
    expect(lastProps(waivedSectionProps)).toMatchObject({ scanId: 's1', projectId: 'p1' })
    expect(lastProps(waivedSectionProps).category).toBe(category)
  })

  it('narrows only All Findings to the severity the link names', () => {
    analyzers.active = ['osv']
    renderPage(`${SCAN_PATH}?severity=CRITICAL`)
    expect(lastProps(findingsTableProps).severity).toBe('CRITICAL')

    cleanup()
    renderPage(`${SCAN_PATH}?tab=security&severity=CRITICAL`)
    expect(lastProps(findingsTableProps).severity).toBeUndefined()
  })

  it('offers the license category filter on the Compliance tab only', () => {
    analyzers.active = ['license_compliance', 'osv']
    renderPage(`${SCAN_PATH}?tab=compliance`)
    expect(screen.getByRole('combobox', { name: 'License category' })).toHaveTextContent('All Categories')
    expect(lastProps(findingsTableProps).licenseCategory).toBeUndefined()

    cleanup()
    renderPage(`${SCAN_PATH}?tab=security`)
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  })

  it('hides historical secrets on the Secrets tab only', () => {
    analyzers.active = ['trufflehog', 'osv']
    renderPage(`${SCAN_PATH}?tab=secrets`)

    fireEvent.click(screen.getByRole('checkbox', { name: 'Hide historical secrets' }))

    expect(findingsTableProps).toHaveBeenLastCalledWith(expect.objectContaining({ category: 'secret', hideHistoricalSecrets: true }))
    cleanup()
    renderPage(`${SCAN_PATH}?tab=security`)
    expect(screen.queryByRole('checkbox', { name: 'Hide historical secrets' })).not.toBeInTheDocument()
  })

  it('applies the direct-dependency and informational filters to the open tab', () => {
    analyzers.active = ['osv']
    renderPage(`${SCAN_PATH}?tab=security`)

    fireEvent.click(screen.getByRole('checkbox', { name: 'Only direct dependencies' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Hide informational' }))

    expect(findingsTableProps).toHaveBeenLastCalledWith(expect.objectContaining({ category: 'security', directOnly: true, hideInfo: true }))
  })
})

describe('ScanDetails metadata', () => {
  const LONG_BRANCH = 'feature/checkout-redesign-with-a-rather-long-branch-name'

  it('lists status, branch, ignored count and every time the scan carries', () => {
    mockUseScan.mockReturnValue({
      data: {
        ...scan('completed_with_errors'),
        error: 'osv: rate limited',
        ignored_count: 7,
        commit_hash: 'abcdef1234567890',
        completed_at: '2026-09-01T00:10:00Z',
        job_started_at: '2026-08-31T23:58:00Z',
      },
      isLoading: false,
    })
    renderPage()

    for (const label of ['Status', 'Branch', 'Commit', 'Ignored', 'Scan Started', 'Scan Completed', 'Pipeline Started']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
    expect(screen.getByText('completed with errors')).toBeInTheDocument()
    expect(screen.getByText('osv: rate limited')).toBeInTheDocument()
    expect(screen.getByText('Ignored').parentElement).toHaveTextContent('7')
  })

  it('leaves out the times and the commit a scan does not carry', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    renderPage()

    expect(screen.getByText('Ignored').parentElement).toHaveTextContent('0')
    for (const label of ['Commit', 'Scan Completed', 'Pipeline Started', 'Pipeline']) {
      expect(screen.queryByText(label)).not.toBeInTheDocument()
    }
  })

  it('charts the severity and the category distribution', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    renderPage()

    expect(screen.getByText('Severity Distribution')).toBeInTheDocument()
    expect(screen.getByText('Category Distribution')).toBeInTheDocument()
  })

  it('breaks a long branch name anywhere inside the card and keeps its icons whole, like the finding id', () => {
    mockUseScan.mockReturnValue({
      data: { ...scan('completed'), branch: LONG_BRANCH, project_url: 'https://gitlab.example.com/acme/shop' },
      isLoading: false,
    })

    renderPage()

    const branch = screen.getByText(LONG_BRANCH)
    expect(branch).toHaveClass('wrap-anywhere')
    expect(branch.closest('a')?.querySelector('svg.lucide-external-link')).toHaveClass('shrink-0')
    expect(branch.closest('a')?.parentElement?.querySelector('svg.lucide-git-branch')).toHaveClass('shrink-0')
  })
  it('gives the metadata card its own row above the two charts until xl, where the three share a row', () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    renderPage()

    const card = screen.getByText('Scan Metadata').closest('.bg-card') as HTMLElement
    expect(card).toHaveClass('md:col-span-2', 'xl:col-span-1')
    expect(card.parentElement).toHaveClass('md:grid-cols-2', 'xl:grid-cols-3')
  })
})

describe('ScanDetails distribution charts', () => {
  async function legendOf(title: string) {
    const card = screen.getByText(title).closest('.bg-card') as HTMLElement
    await waitFor(() => expect(card.querySelectorAll('.recharts-legend-item-text').length).toBeGreaterThan(0))
    return [...card.querySelectorAll('.recharts-legend-item-text')].map((item) => item.textContent)
  }

  it('lists the severities most severe first, in the app\'s severity order', async () => {
    mockUseScan.mockReturnValue({
      data: { ...scan('completed'), stats: { critical: 1, high: 1, medium: 1, low: 1, negligible: 1, info: 1, unknown: 1 } },
      isLoading: false,
    })

    renderPage()

    expect(await legendOf('Severity Distribution')).toEqual(['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Info', 'Unknown'])
  })

  it('writes the legend labels in the theme text colour and keeps each swatch in its slice colour', async () => {
    mockUseScan.mockReturnValue({
      data: { ...scan('completed'), stats: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, info: 0, unknown: 1 } },
      isLoading: false,
    })

    renderPage()

    await legendOf('Severity Distribution')
    const item = screen.getByText('Severity Distribution').closest('.bg-card')!.querySelector('.recharts-legend-item')!
    expect(item.querySelector<HTMLElement>('.recharts-legend-item-text')?.style.color).toBe('hsl(var(--foreground))')
    expect(item.querySelector('path')).toHaveAttribute('fill', SEVERITY_CHART_COLORS.UNKNOWN)
  })

  it('lists the categories in the order of the finding tabs, crypto before other', async () => {
    mockUseScan.mockReturnValue({ data: scan('completed'), isLoading: false })
    categories.stats = { security: 1, secret: 1, sast: 1, compliance: 1, quality: 1, crypto: 1, other: 1 }

    renderPage()

    expect(await legendOf('Category Distribution')).toEqual(['Security', 'Secrets', 'SAST', 'Compliance', 'Quality', 'Crypto', 'Other'])
  })

  it("leaves the legend its own height, like the project overview's pie, so a legend wrapped on a phone stays in its card", async () => {
    mockUseScan.mockReturnValue({
      data: { ...scan('completed'), stats: { critical: 1, high: 1, medium: 1, low: 1, negligible: 1, info: 1, unknown: 1 } },
      isLoading: false,
    })

    renderPage()

    await legendOf('Severity Distribution')
    const card = screen.getByText('Severity Distribution').closest('.bg-card') as HTMLElement
    expect(card.querySelector<HTMLElement>('.recharts-legend-wrapper')?.style.height).not.toBe('36px')
  })
})
