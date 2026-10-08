import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ProjectWaivers } from '@/components/project/ProjectWaivers'
import GlobalWaivers from '@/pages/GlobalWaivers'
import { waiverApi } from '@/api/waivers'
import type { Waiver, WaiversPaginatedResponse } from '@/types/waiver'

const project = vi.hoisted(() => ({ role: 'admin' }))

vi.mock('@/api/waivers', () => ({ waiverApi: { getAll: vi.fn(), delete: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: [], hasPermission: () => false }) }))
vi.mock('@/hooks/queries/use-projects', () => ({
  useProject: () => ({ data: { id: 'p1', name: 'Proj', members: [{ user_id: 'u1', role: project.role }] } }),
}))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { id: 'u1' } }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const WAIVER = {
  id: 'w1',
  project_id: 'p1',
  finding_id: null,
  vulnerability_id: 'CVE-2020-7598',
  package_name: 'minimist',
  package_version: '1.2.0',
  finding_type: null,
  scope: 'finding',
  rule_id: null,
  reason: 'not reachable',
  status: 'accepted_risk',
  expiration_date: null,
  created_by: 'grace',
  created_at: '2026-09-01T00:00:00Z',
  last_eval_scan_id: null,
  last_match_count: 1,
  is_active: true,
} as unknown as Waiver

function page(items: Waiver[], total = items.length): WaiversPaginatedResponse {
  return { items, total, page: 1, size: 50, pages: Math.max(1, Math.ceil(total / 50)) }
}

function renderList(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>)
}

const lastQuery = () => {
  const calls = vi.mocked(waiverApi.getAll).mock.calls
  return calls[calls.length - 1]?.[0]
}

beforeEach(() => {
  vi.clearAllMocks()
  project.role = 'admin'
  vi.mocked(waiverApi.getAll).mockResolvedValue(page([WAIVER]))
  vi.mocked(waiverApi.delete).mockResolvedValue(undefined)
})

describe('the project waiver list', () => {
  it('lists the project waivers without a Created By column', async () => {
    renderList(<ProjectWaivers projectId="p1" />)

    expect(await screen.findByText('minimist')).toBeInTheDocument()
    expect(lastQuery()).toMatchObject({ project_id: 'p1', skip: 0, limit: 50, sort_by: 'created_at', sort_order: 'desc' })
    expect(screen.queryByRole('columnheader', { name: /created by/i })).toBeNull()
  })

  it('sorts by the clicked column, asking the server for expiration_date under Expires', async () => {
    renderList(<ProjectWaivers projectId="p1" />)
    await screen.findByText('minimist')

    fireEvent.click(screen.getByRole('columnheader', { name: /expires/i }))
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort_by: 'expiration_date', sort_order: 'desc' }))

    fireEvent.click(screen.getByRole('columnheader', { name: /expires/i }))
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort_by: 'expiration_date', sort_order: 'asc' }))
  })

  it('narrows to orphaned waivers', async () => {
    renderList(<ProjectWaivers projectId="p1" />)
    await screen.findByText('minimist')

    fireEvent.click(screen.getByRole('checkbox', { name: /only orphaned/i }))

    await waitFor(() => expect(lastQuery()).toMatchObject({ orphaned: true }))
  })

  it('deletes a waiver after confirming the project-scoped wording', async () => {
    renderList(<ProjectWaivers projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Delete waiver' }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Delete Waiver')).toBeInTheDocument()
    expect(dialog).toHaveTextContent('This action cannot be undone.')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(waiverApi.delete).toHaveBeenCalledWith('w1', expect.anything()))
  })

  it('offers neither edit nor delete to a project viewer', async () => {
    project.role = 'viewer'
    renderList(<ProjectWaivers projectId="p1" />)
    await screen.findByText('minimist')

    expect(screen.queryByRole('button', { name: /edit waiver/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /delete waiver/i })).toBeNull()
  })

  it.each([
    [{}, 'No active waivers found.'],
    [{ orphaned: true }, 'No orphaned waivers found.'],
  ])('says why the list is empty (%o)', async (filter, text) => {
    vi.mocked(waiverApi.getAll).mockResolvedValue(page([]))
    renderList(<ProjectWaivers projectId="p1" />)
    if ('orphaned' in filter) fireEvent.click(await screen.findByRole('checkbox', { name: /only orphaned/i }))

    expect(await screen.findByText(text)).toBeInTheDocument()
  })

  it('names an empty search as such', async () => {
    vi.mocked(waiverApi.getAll).mockResolvedValue(page([]))
    renderList(<ProjectWaivers projectId="p1" />)

    fireEvent.change(await screen.findByPlaceholderText('Search waivers...'), { target: { value: 'nothing' } })

    expect(await screen.findByText('No waivers match your search.')).toBeInTheDocument()
  })

  it('reports a failed load', async () => {
    vi.mocked(waiverApi.getAll).mockRejectedValue(new Error('boom'))
    renderList(<ProjectWaivers projectId="p1" />)

    expect(await screen.findByText('Failed to load waivers. Please try again.')).toBeInTheDocument()
  })

  it('offers more rows while the server holds more', async () => {
    vi.mocked(waiverApi.getAll).mockResolvedValue(page([WAIVER], 120))
    renderList(<ProjectWaivers projectId="p1" />)

    expect(await screen.findByText('Scroll to load more')).toBeInTheDocument()
  })
})

describe('the global waiver list', () => {
  it('lists the global waivers with their author, sortable', async () => {
    renderList(<GlobalWaivers />)

    expect(await screen.findByText('grace')).toBeInTheDocument()
    expect(lastQuery()).toMatchObject({ global_only: true, skip: 0, limit: 50 })
    fireEvent.click(screen.getByRole('columnheader', { name: /created by/i }))

    await waitFor(() => expect(lastQuery()).toMatchObject({ sort_by: 'created_by' }))
  })

  it('warns that deleting a global waiver affects every project', async () => {
    renderList(<GlobalWaivers />)
    fireEvent.click(await screen.findByRole('button', { name: /delete .*waiver/i }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Delete Global Waiver')).toBeInTheDocument()
    expect(dialog).toHaveTextContent('This will affect all projects and cannot be undone.')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(waiverApi.delete).toHaveBeenCalledWith('w1', expect.anything()))
  })

  it('says when no global waiver exists', async () => {
    vi.mocked(waiverApi.getAll).mockResolvedValue(page([]))
    renderList(<GlobalWaivers />)

    expect(await screen.findByText('No global waivers found.')).toBeInTheDocument()
  })

  it('keeps the create action on the page', async () => {
    renderList(<GlobalWaivers />)

    expect(await screen.findByRole('button', { name: /create global waiver/i })).toBeInTheDocument()
  })
})
