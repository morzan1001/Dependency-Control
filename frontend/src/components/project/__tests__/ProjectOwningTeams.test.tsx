import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ProjectOwningTeams } from '../ProjectOwningTeams'
import type { Project } from '@/types/project'
import type { Team } from '@/types/team'

const { addTeam, removeTeam, updateProject, useTeamsMock, toastError } = vi.hoisted(() => ({
  addTeam: vi.fn(),
  removeTeam: vi.fn(),
  updateProject: vi.fn(),
  useTeamsMock: vi.fn(),
  toastError: vi.fn(),
}))

vi.mock('@/api/projects', () => ({
  projectApi: { addTeam, removeTeam, update: updateProject },
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => useTeamsMock() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: toastError } }))

function team(id: string, name: string): Team {
  return { id, name, members: [], created_at: '', updated_at: '' }
}

const ALL_TEAMS = [team('t1', 'Payments'), team('t2', 'Platform'), team('t3', 'Identity')]

function project(overrides: Partial<Project> = {}): Project {
  return {
    id: 'p1',
    name: 'acme/widget',
    team_ids: ['t1', 't2'],
    team_sources: { t1: 'gitlab', t2: 'manual' },
    ...overrides,
  } as Project
}

function renderEditor(subject: Project, canManage = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <ProjectOwningTeams project={subject} projectId="p1" canManage={canManage} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  useTeamsMock.mockReturnValue({ data: ALL_TEAMS })
  addTeam.mockResolvedValue(project())
  removeTeam.mockResolvedValue(project())
})

describe('ProjectOwningTeams', () => {
  it('lists every owning team, not just the first', () => {
    renderEditor(project())

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('Platform')).toBeInTheDocument()
  })

  it('adds one owner through the add route and leaves the others in place', async () => {
    renderEditor(project())

    fireEvent.click(screen.getByRole('button', { name: /Add Team/ }))
    fireEvent.click(await screen.findByRole('combobox'))
    fireEvent.click(await screen.findByRole('option', { name: 'Identity' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(addTeam).toHaveBeenCalledWith('p1', 't3'))
    // A whole-set write is what would silently drop an owner a sync added since the page loaded.
    expect(updateProject).not.toHaveBeenCalled()
  })

  it('offers only the teams that do not already own the project', async () => {
    renderEditor(project())

    fireEvent.click(screen.getByRole('button', { name: /Add Team/ }))
    fireEvent.click(await screen.findByRole('combobox'))

    expect(await screen.findByRole('option', { name: 'Identity' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Payments' })).not.toBeInTheDocument()
  })

  it('warns that a provider will re-establish the owner it created', async () => {
    renderEditor(project())

    fireEvent.click(screen.getByRole('button', { name: 'Remove Payments' }))

    expect(await screen.findByText(/next GitLab sync/)).toBeInTheDocument()
    expect(screen.getByText(/change it in GitLab/)).toBeInTheDocument()
  })

  it('says a hand-assigned owner stays removed', async () => {
    renderEditor(project())

    fireEvent.click(screen.getByRole('button', { name: 'Remove Platform' }))

    expect(await screen.findByText(/assigned by hand/)).toBeInTheDocument()
    expect(screen.queryByText(/sync/)).not.toBeInTheDocument()
  })

  it('shows which provider established each owner', () => {
    renderEditor(project())

    expect(screen.getByText('GitLab')).toBeInTheDocument()
    expect(screen.getByText('Manual')).toBeInTheDocument()
  })

  it('removes the owner the confirmation named', async () => {
    renderEditor(project())

    fireEvent.click(screen.getByRole('button', { name: 'Remove Platform' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Remove' }))

    await waitFor(() => expect(removeTeam).toHaveBeenCalledWith('p1', 't2'))
  })

  it('surfaces the last-admin refusal instead of pretending the owner is gone', async () => {
    removeTeam.mockRejectedValue({
      response: { data: { detail: 'A project must keep a team that supplies an admin' } },
    })
    renderEditor(project())

    fireEvent.click(screen.getByRole('button', { name: 'Remove Platform' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Remove' }))

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith('Failed to remove owning team', {
        description: 'A project must keep a team that supplies an admin',
      }),
    )
  })

  it('says an unowned project is unowned and offers nothing to remove', () => {
    renderEditor(project({ team_ids: [], team_sources: {} }))

    expect(screen.getByText('No team owns this project. Only its own members can open it.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Remove / })).not.toBeInTheDocument()
  })

  it('treats a project whose ownership fields are absent as unowned', () => {
    renderEditor({ id: 'p1', name: 'acme/widget' } as Project)

    expect(screen.getByText('No team owns this project. Only its own members can open it.')).toBeInTheDocument()
  })

  it('stops offering to add at the sixteen owners the backend accepts', () => {
    const ids = Array.from({ length: 16 }, (_, i) => `t${i}`)
    renderEditor(project({ team_ids: ids, team_sources: {} }))

    expect(screen.getByRole('button', { name: /Add Team/ })).toBeDisabled()
    expect(screen.getByText(/most owners it may have \(16\)/)).toBeInTheDocument()
  })

  it('shows a reader the owners without any way to change them', () => {
    renderEditor(project(), false)

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add Team/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Remove / })).not.toBeInTheDocument()
  })

  it('still names an owner the reader cannot see by its id', () => {
    renderEditor(project({ team_ids: ['t9'], team_sources: { t9: 'github' } }))

    expect(screen.getByText('t9')).toBeInTheDocument()
    expect(screen.getByText('GitHub')).toBeInTheDocument()
  })
})
