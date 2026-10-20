import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ProjectMembers } from '../ProjectMembers'
import { projectApi } from '@/api/projects'
import { createMutationCache } from '@/lib/mutation-cache'
import type { Project } from '@/types/project'

vi.mock('@/api/projects', () => ({ projectApi: { inviteMember: vi.fn(), updateMember: vi.fn(), removeMember: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: [] }) }))
vi.mock('@/hooks/queries/use-users', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/queries/use-users')>()),
  useCurrentUser: () => ({ data: { id: 'a119abd' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const CO_OWNED = 'Team: Pickachu, The TOURists'
const NO_VERIFIED_USER = 'No user has verified this email address'

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
  beforeEach(() => vi.clearAllMocks())

  it('shows every owning team a member was inherited from, whole and in one badge', () => {
    renderMembers(CO_OWNED)

    expect(screen.getByText(CO_OWNED)).toBeInTheDocument()
  })

  it("stacks Invite Member under the title on a phone, like the waiver list's header", () => {
    renderMembers('')

    const header = screen.getByRole('heading', { name: 'Project Members' }).parentElement?.parentElement
    expect(header).toHaveClass('flex-col', 'sm:flex-row', 'sm:items-center', 'sm:justify-between')
    expect(header).toContainElement(screen.getByRole('button', { name: 'Invite Member' }))
  })

  it('names an empty member list under the table, as the other tables do', () => {
    render(
      <QueryClientProvider client={new QueryClient({ mutationCache: createMutationCache() })}>
        <ProjectMembers project={{ id: 'p1', name: 'acme/widget', members: [] } as Project} projectId="p1" />
      </QueryClientProvider>,
    )

    expect(screen.getByText('No members found.').closest('table')).toBeNull()
  })

  it('leaves a single owner reading as it did', () => {
    renderMembers('Team: The TOURists')

    expect(screen.getByText('Team: The TOURists')).toBeInTheDocument()
  })

  it('outlines the inherited owner pill like every neutral badge, so it stays visible on a hovered row', () => {
    renderMembers('Team: The TOURists')

    expect(screen.getByText('Team: The TOURists')).toHaveClass('border-foreground/45')
    expect(screen.getByText('Team: The TOURists')).not.toHaveClass('border-transparent')
  })

  it('names an invitation that failed and why', async () => {
    vi.mocked(projectApi.inviteMember).mockRejectedValue(new Error('Network Error'))
    renderMembers('')

    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'bob@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to invite member', { description: 'Network Error' }))
    expect(toast.error).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('asks for an email and a role and ends in Cancel and Invite, like the team member dialog', () => {
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))
    const dialog = screen.getByRole('dialog')

    expect(screen.getByLabelText('Email')).toHaveAttribute('type', 'email')
    expect(screen.getByLabelText('Email')).toBeRequired()
    expect(within(dialog).getByLabelText('Role')).toHaveRole('combobox')
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toHaveClass('border')
    expect(within(dialog).getByRole('button', { name: 'Invite' })).toHaveAttribute('type', 'submit')
  })

  it('invites when the form is submitted from the keyboard', async () => {
    vi.mocked(projectApi.inviteMember).mockResolvedValue(undefined as never)
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'bob@example.com' } })
    fireEvent.submit(screen.getByLabelText('Email').closest('form')!)

    await waitFor(() => expect(projectApi.inviteMember).toHaveBeenCalledWith('p1', 'bob@example.com', 'viewer'))
  })

  it('invites a pasted address without the non-breaking spaces around it', async () => {
    vi.mocked(projectApi.inviteMember).mockResolvedValue(undefined as never)
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    // An email field strips the plain spaces around its value itself, so only a pasted non-breaking space reaches the dialog.
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: '\u00a0bob@example.com\u00a0' } })
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }))

    await waitFor(() => expect(projectApi.inviteMember).toHaveBeenCalledWith('p1', 'bob@example.com', 'viewer'))
  })

  it('opens again on the Viewer role after another role was picked and the dialog cancelled', async () => {
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))
    fireEvent.keyDown(within(screen.getByRole('dialog')).getByLabelText('Role'), { key: 'Enter' })
    fireEvent.click(await screen.findByRole('option', { name: 'Admin' }))
    expect(within(screen.getByRole('dialog')).getByLabelText('Role')).toHaveTextContent('Admin')

    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    expect(within(screen.getByRole('dialog')).getByLabelText('Role')).toHaveTextContent('Viewer')
  })

  it('closes without inviting through Cancel', () => {
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'bob@example.com' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(projectApi.inviteMember).not.toHaveBeenCalled()
  })

  it.each(['', '   '])('says under the field that the blank address %j needs an email address and invites no one', async (blank) => {
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: blank } })
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Enter an email address')
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription('Enter an email address')
    expect(projectApi.inviteMember).not.toHaveBeenCalled()
  })

  it.each([
    [404, NO_VERIFIED_USER],
    [400, 'User already a member'],
  ])('shows under the field why the server refused the address (%i), without a toast, like the invite user dialog', async (status, detail) => {
    vi.mocked(projectApi.inviteMember).mockRejectedValue({ response: { status, data: { detail } } })
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'nobody@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(detail)
    expect(screen.getByLabelText('Email')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription(detail)
    expect(toast.error).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'bob@example.com' } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('opens again on an empty field without the refusal shown before it was closed', async () => {
    vi.mocked(projectApi.inviteMember).mockRejectedValue({ response: { status: 404, data: { detail: NO_VERIFIED_USER } } })
    renderMembers('')
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'nobody@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }))
    await screen.findByRole('alert')

    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: 'Invite Member' }))

    expect(screen.getByLabelText('Email')).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
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

describe('ProjectMembers accessible names', () => {
  it('names each role dropdown by its member, as the notification matrix names its boxes', () => {
    renderMembers('')

    expect(screen.getByRole('combobox', { name: 'a119abd: Role' })).toBeInTheDocument()
  })
})
