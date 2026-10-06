import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'

import { UserDetailsDialog } from '../UserDetailsDialog'
import { projectApi } from '@/api/projects'
import { teamApi } from '@/api/teams'

vi.mock('@/api/projects', () => ({ projectApi: { getAll: vi.fn() } }))
vi.mock('@/api/teams', () => ({ teamApi: { getAll: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => true }) }))

describe('UserDetailsDialog while closed', () => {
  it('loads neither the project list nor the teams', () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })

    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <UserDetailsDialog user={null} open={false} onOpenChange={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(projectApi.getAll).not.toHaveBeenCalled()
    expect(teamApi.getAll).not.toHaveBeenCalled()
  })
})
