import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Team } from '@/types/team'

import TeamsPage from '../Teams'

const { updateTeam } = vi.hoisted(() => ({ updateTeam: vi.fn() }))

const TEAM: Team = {
  id: 't-1',
  name: 'Team Beta',
  description: 'Platform squad',
  members: [],
  bindings: [],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

vi.mock('@/hooks/queries/use-teams', () => ({
  useTeams: () => ({ data: [TEAM], isLoading: false, error: null }),
  useUpdateTeam: () => ({ mutate: updateTeam, isPending: false }),
}))
vi.mock('@/hooks/queries/use-users', () => ({ useCurrentUser: () => ({ data: { id: 'u-1' } }) }))
vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ permissions: ['team:update'], hasPermission: (p: string) => p === 'team:update' }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/components/teams/CreateTeamDialog', () => ({ CreateTeamDialog: () => null }))
vi.mock('@/components/teams/TeamMembersDialog', () => ({ TeamMembersDialog: () => null }))
vi.mock('@/components/teams/AddMemberDialog', () => ({ AddMemberDialog: () => null }))
vi.mock('@/components/teams/DeleteTeamDialog', () => ({ DeleteTeamDialog: () => null }))
vi.mock('@/components/teams/TeamWebhooksDialog', () => ({ TeamWebhooksDialog: () => null }))
vi.mock('@/components/teams/TeamBindingDialog', () => ({ TeamBindingDialog: () => null }))

// The card header's only action for a user who may edit but not delete the team.
function editTeam() {
  fireEvent.click(within(screen.getByText(TEAM.name).parentElement as HTMLElement).getByRole('button'))
  return screen.getByRole('dialog')
}

function closeDialog() {
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }))
}

beforeEach(() => {
  vi.clearAllMocks()
  updateTeam.mockImplementation((_vars, options: { onSuccess: () => void }) => options.onSuccess())
})

describe('TeamsPage edit dialog', () => {
  it('keeps the description when the team is renamed on its second edit', () => {
    render(<TeamsPage />)
    editTeam()
    closeDialog()

    const dialog = editTeam()
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Team Gamma' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Team' }))

    expect(updateTeam.mock.calls[0][0]).toEqual({ id: TEAM.id, data: { name: 'Team Gamma', description: TEAM.description } })
  })

  it('drops a cancelled edit', () => {
    render(<TeamsPage />)
    fireEvent.change(within(editTeam()).getByLabelText('Name'), { target: { value: 'Team Gamma' } })
    closeDialog()

    expect(within(editTeam()).getByLabelText('Name')).toHaveValue(TEAM.name)
  })
})
