import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ProjectMembers } from '../ProjectMembers'
import type { Project } from '@/types/project'

vi.mock('@/api/projects', () => ({ projectApi: { inviteMember: vi.fn(), updateMember: vi.fn(), removeMember: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: [] }) }))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { id: 'a119abd' } }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const CO_OWNED = 'Team: Pickachu, The TOURists'

function renderMembers(inheritedFrom: string) {
  const project = {
    id: 'p1',
    name: 'acme/widget',
    members: [{ user_id: 'a119abd', username: 'a119abd', role: 'admin', inherited_from: inheritedFrom }],
  } as Project

  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProjectMembers project={project} projectId="p1" />
    </QueryClientProvider>,
  )
}

describe('ProjectMembers', () => {
  it('shows every owning team a member was inherited from, whole and in one badge', () => {
    renderMembers(CO_OWNED)

    expect(screen.getByText(CO_OWNED)).toBeInTheDocument()
  })

  it('leaves a single owner reading as it did', () => {
    renderMembers('Team: The TOURists')

    expect(screen.getByText('Team: The TOURists')).toBeInTheDocument()
  })
})
