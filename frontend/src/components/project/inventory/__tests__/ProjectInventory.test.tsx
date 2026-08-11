import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ProjectInventory } from '../ProjectInventory'
import * as inventoryApiModule from '@/api/inventory'
import * as projectHooks from '@/hooks/queries/use-projects'

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
      <ProjectInventory projectId="p1" defaultBranch="main" projectName="proj" />
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
    vi.mocked(inventoryApiModule.inventoryApi.getStats).mockRejectedValue(new Error('404'))

    renderInventory()

    await waitFor(() => expect(screen.getByText(/no completed scan/i)).toBeInTheDocument())
  })

  it('shows an empty state when the project has no active branches', async () => {
    vi.mocked(projectHooks.useProjectBranches).mockReturnValue({
      data: [],
    } as ReturnType<typeof projectHooks.useProjectBranches>)

    renderInventory()

    await waitFor(() => expect(screen.getByText(/no active branches/i)).toBeInTheDocument())
    expect(inventoryApiModule.inventoryApi.getStats).not.toHaveBeenCalled()
    expect(screen.queryByText('Components')).not.toBeInTheDocument()
  })
})
