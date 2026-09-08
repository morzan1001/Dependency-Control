import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectSettings } from '../ProjectSettings'
import type { Project } from '@/types/project'
import type { User } from '@/types/user'

const mockUpdate = vi.fn().mockResolvedValue({})
const mockUseGitHubInstances = vi.fn()

vi.mock('@/api/projects', () => ({
  projectApi: {
    update: (...args: unknown[]) => mockUpdate(...args),
    delete: vi.fn(),
    rotateApiKey: vi.fn(),
  },
}))
vi.mock('@/hooks/queries/use-system', () => ({ useAppConfig: () => ({ data: undefined }) }))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-projects', () => ({
  projectKeys: { detail: (id: string) => ['project', id] },
  useProjectBranches: () => ({ data: [] }),
  useUpdateProjectNotifications: () => ({ mutate: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/queries/use-webhooks', () => ({
  useProjectWebhooks: () => ({ data: [], isLoading: false, refetch: vi.fn() }),
  useCreateProjectWebhook: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteWebhook: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/hooks/queries/use-instances', () => ({
  useGitLabInstances: () => ({ data: { items: [] } }),
  useGitHubInstances: () => mockUseGitHubInstances(),
}))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ permissions: [] }) }))
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/components/WebhookManager', () => ({ WebhookManager: () => <div /> }))
vi.mock('@/pages/project/CryptoPolicyOverridePage', () => ({ CryptoPolicyOverridePage: () => <div /> }))
vi.mock('../AnalyzerSettingsDialog', () => ({ AnalyzerSettingsDialog: () => null }))

const USER: User = {
  id: 'u1',
  username: 'u1',
  email: 'u1@test.com',
  is_active: true,
  permissions: [],
  totp_enabled: false,
}

function githubInstances(hasToken: boolean) {
  return {
    data: {
      items: [
        {
          id: 'gh-1',
          name: 'GitHub.com',
          url: 'https://github.com',
          is_active: true,
          auto_create_projects: true,
          has_access_token: hasToken,
          created_at: '',
          created_by: 'a',
        },
      ],
    },
  }
}

function githubProject(overrides: Partial<Project> = {}): Project {
  return {
    id: 'p1',
    name: 'acme/widget',
    members: [{ user_id: 'u1', role: 'admin' }],
    active_analyzers: [],
    github_instance_id: 'gh-1',
    github_repository_id: '42',
    github_repository_path: 'acme/widget',
    ...overrides,
  } as Project
}

function renderSettings(project: Project) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <ProjectSettings project={project} projectId="p1" user={USER} />
    </QueryClientProvider>,
  )
}

describe('ProjectSettings GitHub PR decoration', () => {
  beforeEach(() => {
    mockUpdate.mockClear()
    mockUseGitHubInstances.mockReturnValue(githubInstances(true))
  })

  it('sends the toggle state with the settings form', async () => {
    renderSettings(githubProject())

    fireEvent.click(screen.getByLabelText('Pull Request Decoration'))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: true })
  })

  it('round-trips an already-enabled project', async () => {
    renderSettings(githubProject({ github_pr_comments_enabled: true }))

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: true })
  })

  it('disables the toggle when the linked instance has no token', () => {
    mockUseGitHubInstances.mockReturnValue(githubInstances(false))

    renderSettings(githubProject())

    expect(screen.getByLabelText('Pull Request Decoration')).toBeDisabled()
    expect(screen.getByText('Requires an access token on the GitHub instance.')).toBeInTheDocument()
  })

  it('shows nothing for a GitLab-sourced project', () => {
    renderSettings(githubProject({ github_instance_id: undefined, gitlab_instance_id: 'gl-1' }))

    expect(screen.queryByLabelText('Pull Request Decoration')).toBeNull()
  })
})
