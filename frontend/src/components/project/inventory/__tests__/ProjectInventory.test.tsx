import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ProjectInventory } from '../ProjectInventory'
import * as inventoryApiModule from '@/api/inventory'
import * as projectHooks from '@/hooks/queries/use-projects'
import type { BranchInfo } from '@/types/project'

vi.mock('@/api/inventory')
vi.mock('@/hooks/queries/use-projects')

const stats = {
  scan: { scan_id: 's1', branch: 'main', created_at: '2026-08-10T12:00:00Z', commit_hash: 'abcdef1234' },
  components_total: 42, direct_count: 10, transitive_count: 32,
  license_count: 7, ecosystem_count: 2, crypto_asset_count: 3,
}

function renderInventory() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ProjectInventory projectId="p1" defaultBranch="main" />
    </QueryClientProvider>,
  )
}

describe('ProjectInventory', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('renders stat tiles for the default branch', async () => {
    vi.mocked(projectHooks.useProjectBranches).mockReturnValue({
      data: [{ name: 'main', is_active: true }, { name: 'old', is_active: false }],
    } as ReturnType<typeof projectHooks.useProjectBranches>)
    vi.mocked(inventoryApiModule.inventoryApi.getStats).mockResolvedValue(stats)

    renderInventory()

    await waitFor(() => expect(screen.getByText('42')).toBeInTheDocument())
    expect(inventoryApiModule.inventoryApi.getStats).toHaveBeenCalledWith('p1', 'main')
    expect(screen.getByText(/10 direct/i)).toBeInTheDocument()
  })

  it('shows an empty state when the branch has no completed scan', async () => {
    vi.mocked(projectHooks.useProjectBranches).mockReturnValue({
      data: [{ name: 'main', is_active: true }],
    } as ReturnType<typeof projectHooks.useProjectBranches>)
    vi.mocked(inventoryApiModule.inventoryApi.getStats).mockRejectedValue(
      Object.assign(new Error('not found'), { response: { status: 404 } }),
    )

    renderInventory()

    await waitFor(() => expect(screen.getByText(/no completed scan/i)).toBeInTheDocument())
  })

  it('shows a generic error card with retry for non-404 stats failures', async () => {
    // status 400 (not 404) fails fast under retryUnlessClientError, unlike a 5xx which would retry first.
    vi.mocked(projectHooks.useProjectBranches).mockReturnValue({
      data: [{ name: 'main', is_active: true }],
    } as ReturnType<typeof projectHooks.useProjectBranches>)
    vi.mocked(inventoryApiModule.inventoryApi.getStats)
      .mockRejectedValueOnce(Object.assign(new Error('bad request'), { response: { status: 400 } }))
      .mockResolvedValueOnce(stats)

    renderInventory()

    await waitFor(() => expect(screen.getByText(/could not load inventory/i)).toBeInTheDocument())
    expect(screen.queryByText(/no completed scan/i)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => expect(screen.getByText('42')).toBeInTheDocument())
  })

  it('opens a newly picked branch on the first page of each table, keeping the search', async () => {
    vi.mocked(projectHooks.useProjectBranches).mockReturnValue({
      data: [{ name: 'main', is_active: true }, { name: 'dev', is_active: true }],
    } as ReturnType<typeof projectHooks.useProjectBranches>)
    const api = vi.mocked(inventoryApiModule.inventoryApi)
    api.getStats.mockResolvedValue(stats)
    api.getLicenses.mockResolvedValue({ scan: stats.scan, items: [] })
    api.getComponents.mockImplementation(async (_, params) => ({
      scan: stats.scan, total: 50, page: params?.page ?? 1, page_size: 25,
      items: [{ name: `lodash-${params?.branch}-${params?.page}`, version: '1', latest_version: null, ecosystem: 'npm',
        license: null, license_category: null, direct: true, eol: false, outdated: false, purl: null }],
    }))
    api.getCrypto.mockImplementation(async (_, params) => ({
      scan: stats.scan, total: 50, page: params?.page ?? 1, page_size: 25,
      items: [{ name: `rsa-${params?.branch}-${params?.page}`, asset_type: 'algorithm', primitive: 'pke', variant: 'RSA',
        key_size_bits: 2048, location_count: 1, locations: [] }],
    }))

    renderInventory()
    fireEvent.change(await screen.findByPlaceholderText('Search components…'), { target: { value: 'lod' } })
    await waitFor(() => expect(api.getComponents).toHaveBeenCalledWith('p1', expect.objectContaining({ search: 'lod' })))
    await screen.findByText('lodash-main-1')
    await screen.findByText('rsa-main-1')
    for (const next of screen.getAllByRole('button', { name: /next/i })) fireEvent.click(next)
    await screen.findByText('lodash-main-2')
    await screen.findByText('rsa-main-2')

    fireEvent.click(screen.getByRole('combobox'))
    fireEvent.click(screen.getByRole('option', { name: 'dev' }))

    await screen.findByText('lodash-dev-1')
    await screen.findByText('rsa-dev-1')
    const devPages = (calls: { branch?: string; page?: number }[]) =>
      calls.filter((params) => params.branch === 'dev').map((params) => params.page)
    expect(devPages(api.getComponents.mock.calls.map(([, params]) => params ?? {}))).toEqual([1])
    expect(devPages(api.getCrypto.mock.calls.map(([, params]) => params ?? {}))).toEqual([1])
    expect(api.getComponents).toHaveBeenLastCalledWith('p1', expect.objectContaining({ branch: 'dev', search: 'lod' }))
  })

  it('shows an empty state when the project has no active branches', async () => {
    vi.mocked(projectHooks.useProjectBranches).mockReturnValue({
      data: [] as BranchInfo[],
    } as ReturnType<typeof projectHooks.useProjectBranches>)

    renderInventory()

    await waitFor(() => expect(screen.getByText(/no active branches/i)).toBeInTheDocument())
    expect(inventoryApiModule.inventoryApi.getStats).not.toHaveBeenCalled()
    expect(screen.queryByText('Components')).not.toBeInTheDocument()
  })
})
