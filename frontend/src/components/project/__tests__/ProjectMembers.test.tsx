import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { toast } from 'sonner'
import { describe, expect, it, vi } from 'vitest'

import { ProjectMembers } from '../ProjectMembers'
import { projectApi } from '@/api/projects'
import { createMutationCache } from '@/lib/mutation-cache'
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
    <QueryClientProvider client={new QueryClient({ mutationCache: createMutationCache(), defaultOptions: { queries: { retry: false } } })}>
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

  it('names an invitation that failed and why', async () => {
    vi.mocked(projectApi.inviteMember).mockRejectedValue(new Error('Network Error'))
    renderMembers('')

    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'bob@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to invite member', { description: 'Network Error' }))
  })

  it('names a role change that failed and why', async () => {
    vi.mocked(projectApi.updateMember).mockRejectedValue(new Error('Network Error'))
    renderMembers('')

    fireEvent.keyDown(within(screen.getByRole('table')).getByRole('combobox'), { key: 'Enter' })
    fireEvent.click(await screen.findByRole('option', { name: 'Viewer' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to update member role', { description: 'Network Error' }))
  })

  it('names a removal that failed and why', async () => {
    vi.mocked(projectApi.removeMember).mockRejectedValue(new Error('Network Error'))
    renderMembers('')

    fireEvent.click(within(screen.getByRole('table')).getByRole('button'))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to remove member', { description: 'Network Error' }))
  })
})
