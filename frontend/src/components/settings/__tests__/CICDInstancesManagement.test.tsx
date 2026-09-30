import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { CICDInstancesManagement } from '../CICDInstancesManagement'
import type { GitHubInstance } from '@/types/github'
import type { GitLabInstance } from '@/types/gitlab'

const mockGitHubCreate = vi.fn().mockResolvedValue({})
const mockGitHubUpdate = vi.fn().mockResolvedValue({})
const mockGitLabUpdate = vi.fn().mockResolvedValue({})
const mockUseGitHubInstances = vi.fn()
const mockUseGitLabInstances = vi.fn()

vi.mock('@/api/gitlab-instances', () => ({
  gitlabInstancesApi: {
    create: vi.fn(),
    update: (...args: unknown[]) => mockGitLabUpdate(...args),
    delete: vi.fn(),
    testConnection: vi.fn(),
  },
}))
vi.mock('@/api/github-instances', () => ({
  githubInstancesApi: {
    create: (...args: unknown[]) => mockGitHubCreate(...args),
    update: (...args: unknown[]) => mockGitHubUpdate(...args),
    delete: vi.fn(),
    testConnection: vi.fn(),
  },
}))
vi.mock('@/hooks/queries/use-instances', () => ({
  gitlabInstanceKeys: { all: ['gitlab-instances'] },
  githubInstanceKeys: { all: ['github-instances'] },
  useGitLabInstances: () => mockUseGitLabInstances(),
  useGitHubInstances: () => mockUseGitHubInstances(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function githubInstance(overrides: Partial<GitHubInstance> = {}) {
  return {
    data: {
      items: [
        {
          id: 'gh-1',
          name: 'GitHub.com',
          url: 'https://token.actions.githubusercontent.com',
          github_url: 'https://github.com',
          is_active: true,
          oidc_audience: 'dependency-control',
          auto_create_projects: false,
          sync_teams: false,
          allowed_owner_ids: [],
          token_configured: true,
          created_at: '2026-09-01T00:00:00Z',
          created_by: 'admin',
          ...overrides,
        },
      ],
    },
    isLoading: false,
  }
}

function gitlabInstance(overrides: Partial<GitLabInstance> = {}) {
  return {
    data: {
      items: [
        {
          id: 'gl-1',
          name: 'Internal GitLab',
          url: 'https://gitlab.example.com',
          is_active: true,
          auto_create_projects: false,
          sync_teams: true,
          team_sync_depth: 1,
          allowed_namespaces: [],
          token_configured: true,
          created_at: '2026-09-01T00:00:00Z',
          created_by: 'admin',
          ...overrides,
        },
      ],
    },
    isLoading: false,
  }
}

// The row actions are icon-only buttons: Test, Edit, Delete.
function openEditDialog(name: RegExp) {
  const row = screen.getByRole('row', { name })
  fireEvent.click(within(row).getAllByRole('button')[1])
  return screen.getByRole('dialog')
}

function renderManagement() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <CICDInstancesManagement />
    </QueryClientProvider>,
  )
}

describe('CICDInstancesManagement GitHub team sync', () => {
  beforeEach(() => {
    mockGitHubCreate.mockClear()
    mockGitHubUpdate.mockClear()
    mockUseGitLabInstances.mockReturnValue({ data: { items: [] }, isLoading: false })
    mockUseGitHubInstances.mockReturnValue(githubInstance())
  })

  it('sends sync_teams with the GitHub update payload', async () => {
    renderManagement()

    const dialog = openEditDialog(/GitHub\.com/)
    fireEvent.click(within(dialog).getByLabelText('Sync Teams'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Instance' }))

    await waitFor(() => expect(mockGitHubUpdate).toHaveBeenCalled())
    expect(mockGitHubUpdate.mock.calls[0][1]).toMatchObject({ sync_teams: true })
  })

  it('round-trips an instance that already syncs teams', async () => {
    mockUseGitHubInstances.mockReturnValue(githubInstance({ sync_teams: true }))

    renderManagement()

    const dialog = openEditDialog(/GitHub\.com/)
    expect(within(dialog).getByLabelText('Sync Teams')).toBeChecked()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Instance' }))

    await waitFor(() => expect(mockGitHubUpdate).toHaveBeenCalled())
    expect(mockGitHubUpdate.mock.calls[0][1]).toMatchObject({ sync_teams: true })
  })

  it('badges a GitHub instance that syncs teams', () => {
    mockUseGitHubInstances.mockReturnValue(githubInstance({ sync_teams: true }))

    renderManagement()

    expect(within(screen.getByRole('table')).getByText('Sync Teams')).toBeInTheDocument()
  })

  it('badges each provider whose instance holds no token', () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance({ token_configured: false }))
    mockUseGitHubInstances.mockReturnValue(githubInstance({ token_configured: false }))

    renderManagement()

    const table = within(screen.getByRole('table'))
    expect(table.getByText('No Token')).toBeInTheDocument()
    expect(table.getByText('No PAT')).toBeInTheDocument()
  })

  it('badges no instance that holds a token', () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance())

    renderManagement()

    const table = within(screen.getByRole('table'))
    expect(table.queryByText('No Token')).toBeNull()
    expect(table.queryByText('No PAT')).toBeNull()
  })

  // Spec §8: GHES has no IdP team sync, so its teams may be hand-maintained and less
  // authoritative than an operator expects.
  it('warns that GHES team structure is hand-maintained once sync is on', () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance())
    mockUseGitHubInstances.mockReturnValue(githubInstance({ sync_teams: true }))

    renderManagement()

    const gitlabDialog = openEditDialog(/Internal GitLab/)
    expect(within(gitlabDialog).queryByText(/Enterprise Server has no IdP team sync/)).toBeNull()
    fireEvent.click(within(gitlabDialog).getByRole('button', { name: 'Cancel' }))

    expect(within(openEditDialog(/GitHub\.com/)).getByText(/Enterprise Server has no IdP team sync/)).toBeInTheDocument()
  })

  it('keeps the depth select GitLab-only', () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance())
    mockUseGitHubInstances.mockReturnValue(githubInstance({ sync_teams: true }))

    renderManagement()

    const gitlabDialog = openEditDialog(/Internal GitLab/)
    expect(within(gitlabDialog).getByLabelText('Team Sync Depth')).toBeInTheDocument()
    fireEvent.click(within(gitlabDialog).getByRole('button', { name: 'Cancel' }))

    expect(within(openEditDialog(/GitHub\.com/)).queryByLabelText('Team Sync Depth')).toBeNull()
  })

  function openGitHubCreateDialog() {
    fireEvent.click(screen.getByRole('button', { name: 'Add Instance' }))

    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('combobox'))
    fireEvent.click(screen.getByRole('option', { name: 'GitHub' }))

    fireEvent.change(within(dialog).getByLabelText('Name *'), { target: { value: 'GitHub.com' } })
    fireEvent.change(within(dialog).getByLabelText('OIDC Issuer URL *'), {
      target: { value: 'https://token.actions.githubusercontent.com' },
    })
    return dialog
  }

  it('sends sync_teams with the GitHub create payload', async () => {
    renderManagement()

    const dialog = openGitHubCreateDialog()
    fireEvent.change(within(dialog).getByLabelText('Access Token'), { target: { value: 'ghp_x' } })
    fireEvent.click(within(dialog).getByLabelText('Sync Teams'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Instance' }))

    await waitFor(() => expect(mockGitHubCreate).toHaveBeenCalled())
    expect(mockGitHubCreate.mock.calls[0][0]).toMatchObject({ sync_teams: true })
  })

  // The switch needs a token to be operable, but clearing the field afterwards leaves it on.
  // Without the guard the backend answers a raw 422 envelope instead of the update path's sentence.
  it('refuses to create a tokenless GitHub instance that syncs teams', () => {
    renderManagement()

    const dialog = openGitHubCreateDialog()
    fireEvent.change(within(dialog).getByLabelText('Access Token'), { target: { value: 'ghp_x' } })
    fireEvent.click(within(dialog).getByLabelText('Sync Teams'))
    fireEvent.change(within(dialog).getByLabelText('Access Token'), { target: { value: '' } })

    expect(within(dialog).getByLabelText('Sync Teams')).toBeChecked()
    expect(within(dialog).getByRole('button', { name: 'Create Instance' })).toBeDisabled()
  })
})

describe('CICDInstancesManagement owner and namespace allowlists', () => {
  beforeEach(() => {
    mockGitHubCreate.mockClear()
    mockGitHubUpdate.mockClear()
    mockGitLabUpdate.mockClear()
    mockUseGitLabInstances.mockReturnValue({ data: { items: [] }, isLoading: false })
    mockUseGitHubInstances.mockReturnValue(githubInstance())
  })

  function openGitHubCreateDialog(url = 'https://token.actions.githubusercontent.com') {
    fireEvent.click(screen.getByRole('button', { name: 'Add Instance' }))

    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('combobox'))
    fireEvent.click(screen.getByRole('option', { name: 'GitHub' }))

    fireEvent.change(within(dialog).getByLabelText('Name *'), { target: { value: 'GitHub.com' } })
    fireEvent.change(within(dialog).getByLabelText('OIDC Issuer URL *'), { target: { value: url } })
    return dialog
  }

  it('explains why github.com needs the owner list', () => {
    renderManagement()

    const dialog = openEditDialog(/GitHub\.com/)
    expect(within(dialog).getByLabelText('Allowed Owner IDs')).toBeInTheDocument()
    expect(within(dialog).getByText(/every repository on github\.com/i)).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('Allowed Namespaces')).toBeNull()
  })

  it('sends the parsed owner ids with the GitHub create payload', async () => {
    renderManagement()

    const dialog = openGitHubCreateDialog()
    fireEvent.change(within(dialog).getByLabelText('Allowed Owner IDs'), { target: { value: '111, 222' } })
    fireEvent.click(within(dialog).getByLabelText('Auto-Create Projects'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Instance' }))

    await waitFor(() => expect(mockGitHubCreate).toHaveBeenCalled())
    expect(mockGitHubCreate.mock.calls[0][0]).toMatchObject({
      auto_create_projects: true,
      allowed_owner_ids: ['111', '222'],
    })
  })

  // Without the guard the backend answers a raw 422 envelope instead of a sentence.
  it('refuses to create a github.com instance that auto-creates for every owner', () => {
    renderManagement()

    const dialog = openGitHubCreateDialog()
    fireEvent.click(within(dialog).getByLabelText('Auto-Create Projects'))

    expect(within(dialog).getByRole('button', { name: 'Create Instance' })).toBeDisabled()
    expect(within(dialog).getByText(/needs at least one owner id/i)).toBeInTheDocument()

    fireEvent.change(within(dialog).getByLabelText('Allowed Owner IDs'), { target: { value: '111' } })
    expect(within(dialog).getByRole('button', { name: 'Create Instance' })).toBeEnabled()
  })

  it('lets a GHES instance auto-create without an owner list', () => {
    renderManagement()

    const dialog = openGitHubCreateDialog('https://github.corp.example.com/_services/token')
    fireEvent.click(within(dialog).getByLabelText('Auto-Create Projects'))

    expect(within(dialog).getByRole('button', { name: 'Create Instance' })).toBeEnabled()
  })

  it('round-trips the stored owner list through the edit dialog', async () => {
    mockUseGitHubInstances.mockReturnValue(githubInstance({ allowed_owner_ids: ['111', '222'] }))

    renderManagement()

    const dialog = openEditDialog(/GitHub\.com/)
    expect(within(dialog).getByLabelText('Allowed Owner IDs')).toHaveValue('111, 222')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Instance' }))

    await waitFor(() => expect(mockGitHubUpdate).toHaveBeenCalled())
    expect(mockGitHubUpdate.mock.calls[0][1]).toMatchObject({ allowed_owner_ids: ['111', '222'] })
  })

  it('clears the owner list when the field is emptied', async () => {
    mockUseGitHubInstances.mockReturnValue(githubInstance({ allowed_owner_ids: ['111'] }))

    renderManagement()

    const dialog = openEditDialog(/GitHub\.com/)
    fireEvent.change(within(dialog).getByLabelText('Allowed Owner IDs'), { target: { value: '' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Instance' }))

    await waitFor(() => expect(mockGitHubUpdate).toHaveBeenCalled())
    expect(mockGitHubUpdate.mock.calls[0][1]).toMatchObject({ allowed_owner_ids: [] })
  })

  it('edits the namespace list of a GitLab instance and explains gitlab.com', async () => {
    mockUseGitLabInstances.mockReturnValue(
      gitlabInstance({ name: 'GitLab.com', url: 'https://gitlab.com', allowed_namespaces: ['acme'] }),
    )
    mockUseGitHubInstances.mockReturnValue({ data: { items: [] }, isLoading: false })

    renderManagement()

    const dialog = openEditDialog(/GitLab\.com/)
    expect(within(dialog).getByText(/every project on gitlab\.com/i)).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('Allowed Owner IDs')).toBeNull()
    const field = within(dialog).getByLabelText('Allowed Namespaces')
    expect(field).toHaveValue('acme')
    fireEvent.change(field, { target: { value: 'acme acme-labs' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Instance' }))

    await waitFor(() => expect(mockGitLabUpdate).toHaveBeenCalled())
    expect(mockGitLabUpdate.mock.calls[0][1]).toMatchObject({ allowed_namespaces: ['acme', 'acme-labs'] })
  })

  it('offers no default-instance flag on a GitLab instance', async () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance())
    mockUseGitHubInstances.mockReturnValue({ data: { items: [] }, isLoading: false })

    renderManagement()

    expect(within(screen.getByRole('table')).queryByText('Default')).toBeNull()
    const dialog = openEditDialog(/Internal GitLab/)
    expect(within(dialog).queryByLabelText('Default Instance')).toBeNull()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Update Instance' }))

    await waitFor(() => expect(mockGitLabUpdate).toHaveBeenCalled())
    expect(mockGitLabUpdate.mock.calls[0][1]).not.toHaveProperty('is_default')
  })
})

describe('CICDInstancesManagement delete confirmation', () => {
  it('states that linked instances are refused and what a delete takes from teams', () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance())
    mockUseGitHubInstances.mockReturnValue({ data: { items: [] }, isLoading: false })

    renderManagement()

    const row = screen.getByRole('row', { name: /Internal GitLab/ })
    fireEvent.click(within(row).getAllByRole('button')[2])
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('its team bindings and every team membership its sync added')
    expect(dialog).toHaveTextContent('A team whose only admin came from this sync is left without one')
    expect(dialog).toHaveTextContent('An instance that projects still link to is refused')
    expect(dialog).not.toHaveTextContent('lose their CI/CD integration')
  })
})
