import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ProjectWaivers } from '../ProjectWaivers'
import { waiverApi } from '@/api/waivers'

vi.mock('@/api/waivers', () => ({ waiverApi: { getAll: vi.fn(), delete: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: [] }) }))
vi.mock('@/hooks/queries/use-projects', () => ({ useProject: () => ({ data: undefined }) }))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: undefined }) }))

describe('ProjectWaivers', () => {
  it('keeps the search box mounted while the next search loads', async () => {
    vi.mocked(waiverApi.getAll)
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, size: 50, pages: 1 })
      .mockReturnValueOnce(new Promise(() => {}))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <ProjectWaivers projectId="p1" />
      </QueryClientProvider>,
    )

    const search = await screen.findByPlaceholderText('Search waivers...')
    fireEvent.change(search, { target: { value: 'lodash' } })
    await waitFor(() => expect(waiverApi.getAll).toHaveBeenCalledTimes(2))

    expect(screen.queryByPlaceholderText('Search waivers...')).toBe(search)
  })
})
