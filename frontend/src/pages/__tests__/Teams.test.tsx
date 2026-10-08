import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { teamApi } from '@/api/teams'
import type { Team } from '@/types/team'

import TeamsPage from '../Teams'

const TEAM: Team = {
  id: 't-1',
  name: 'Team Beta',
  description: 'Platform squad',
  members: [],
  bindings: [],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}
const PLATFORM: Team = { ...TEAM, id: 't-2', name: 'Platform' }

vi.mock('@/api/teams', () => ({ teamApi: { getAll: vi.fn(), update: vi.fn() } }))
vi.mock('@/api/users', () => ({ userApi: { getMe: () => Promise.resolve({ id: 'u-1' }) } }))
vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ permissions: ['team:update'], hasPermission: (p: string) => p === 'team:update' }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/components/teams/TeamMembersDialog', () => ({
  TeamMembersDialog: ({ team, isOpen }: { team: Team | null; isOpen: boolean }) =>
    isOpen ? <div data-testid="members-dialog">{team?.id}</div> : null,
}))
vi.mock('@/components/teams/AddMemberDialog', () => ({ AddMemberDialog: () => null }))
vi.mock('@/components/teams/DeleteTeamDialog', () => ({ DeleteTeamDialog: () => null }))
vi.mock('@/components/teams/TeamWebhooksDialog', () => ({ TeamWebhooksDialog: () => null }))
vi.mock('@/components/teams/TeamBindingDialog', () => ({ TeamBindingDialog: () => null }))

async function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <TeamsPage />
    </QueryClientProvider>,
  )
  await screen.findByText(TEAM.name)
  return client
}

// The card header's only action for a user who may edit but not delete the team.
function editTeam(name = TEAM.name) {
  fireEvent.click(within(screen.getByText(name).parentElement as HTMLElement).getByRole('button'))
  return screen.getByRole('dialog')
}

function closeDialog() {
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }))
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(teamApi.getAll).mockResolvedValue([TEAM])
})

describe('TeamsPage edit dialog', () => {
  it('keeps the description when the team is renamed on its second edit', async () => {
    await renderPage()
    editTeam()
    closeDialog()

    const dialog = editTeam()
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Team Gamma' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Team' }))

    await waitFor(() =>
      expect(teamApi.update).toHaveBeenCalledWith(TEAM.id, { name: 'Team Gamma', description: TEAM.description }),
    )
  })

  it('drops a cancelled edit', async () => {
    await renderPage()
    fireEvent.change(within(editTeam()).getByLabelText('Name'), { target: { value: 'Team Gamma' } })
    closeDialog()

    expect(within(editTeam()).getByLabelText('Name')).toHaveValue(TEAM.name)
  })

  it('stays open until the refetched team list holds the new name', async () => {
    const renamed = { ...TEAM, name: 'Team Gamma' }
    let answerRefetch: (teams: Team[]) => void = () => undefined
    vi.mocked(teamApi.getAll)
      .mockResolvedValueOnce([TEAM])
      .mockReturnValueOnce(new Promise((resolve) => (answerRefetch = resolve)))
    vi.mocked(teamApi.update).mockResolvedValue(renamed)
    await renderPage()
    const dialog = editTeam()
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: renamed.name } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Team' }))
    // The save runs on microtasks only, so a dialog that closes on the PUT alone is gone after one task.
    await act(() => new Promise((resolve) => setTimeout(resolve, 0)))

    expect(teamApi.getAll).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: 'Updating...' })).toBeDisabled()

    answerRefetch([renamed])
    await screen.findByText(renamed.name)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    expect(within(editTeam(renamed.name)).getByLabelText('Name')).toHaveValue(renamed.name)
  })

  it('stays shut for the next team clicked after the edited team left the list', async () => {
    vi.mocked(teamApi.getAll).mockResolvedValueOnce([TEAM, PLATFORM]).mockResolvedValue([PLATFORM])
    const client = await renderPage()
    editTeam()
    await client.invalidateQueries()
    await waitFor(() => expect(screen.queryByText(TEAM.name)).not.toBeInTheDocument())

    fireEvent.click(screen.getByText(PLATFORM.name))

    expect(screen.getByTestId('members-dialog')).toHaveTextContent(PLATFORM.id)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
