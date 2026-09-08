import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { CICDInstancesManagement } from '../CICDInstancesManagement'
import type { GitHubInstance } from '@/types/github'

const mockGitHubCreate = vi.fn().mockResolvedValue({})
const mockGitHubUpdate = vi.fn().mockResolvedValue({})
const mockUseGitHubInstances = vi.fn()
const mockUseGitLabInstances = vi.fn()

vi.mock('@/api/gitlab-instances', () => ({
  gitlabInstancesApi: { create: vi.fn(), update: vi.fn(), delete: vi.fn(), testConnection: vi.fn() },
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
          has_access_token: true,
          created_at: '2026-09-01T00:00:00Z',
          created_by: 'admin',
          ...overrides,
        },
      ],
    },
    isLoading: false,
  }
}

function gitlabInstance() {
  return {
    data: {
      items: [
        {
          id: 'gl-1',
          name: 'Internal GitLab',
          url: 'https://gitlab.example.com',
          is_active: true,
          is_default: true,
          auto_create_projects: false,
          sync_teams: true,
          team_sync_depth: 1,
          token_configured: true,
          created_at: '2026-09-01T00:00:00Z',
          created_by: 'admin',
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

  it('keeps the depth select GitLab-only', () => {
    mockUseGitLabInstances.mockReturnValue(gitlabInstance())
    mockUseGitHubInstances.mockReturnValue(githubInstance({ sync_teams: true }))

    renderManagement()

    const gitlabDialog = openEditDialog(/Internal GitLab/)
    expect(within(gitlabDialog).getByLabelText('Team Sync Depth')).toBeInTheDocument()
    fireEvent.click(within(gitlabDialog).getByRole('button', { name: 'Cancel' }))

    expect(within(openEditDialog(/GitHub\.com/)).queryByLabelText('Team Sync Depth')).toBeNull()
  })

  it('sends sync_teams with the GitHub create payload', async () => {
    renderManagement()

    fireEvent.click(screen.getByRole('button', { name: 'Add Instance' }))

    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('combobox'))
    fireEvent.click(screen.getByRole('option', { name: 'GitHub' }))

    fireEvent.change(within(dialog).getByLabelText('Name *'), { target: { value: 'GitHub.com' } })
    fireEvent.change(within(dialog).getByLabelText('OIDC Issuer URL *'), {
      target: { value: 'https://token.actions.githubusercontent.com' },
    })
    fireEvent.change(within(dialog).getByLabelText('Access Token'), { target: { value: 'ghp_x' } })
    fireEvent.click(within(dialog).getByLabelText('Sync Teams'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Instance' }))

    await waitFor(() => expect(mockGitHubCreate).toHaveBeenCalled())
    expect(mockGitHubCreate.mock.calls[0][0]).toMatchObject({ sync_teams: true })
  })
})
