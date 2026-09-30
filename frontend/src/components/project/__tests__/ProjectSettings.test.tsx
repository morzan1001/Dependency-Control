import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectSettings } from '../ProjectSettings'
import type { Project } from '@/types/project'
import type { AppConfig } from '@/types/system'
import type { User } from '@/types/user'

const mockUpdate = vi.fn().mockResolvedValue({})
const mockUseGitHubInstances = vi.fn()
const mockUseGitLabInstances = vi.fn()
const mockUseTeams = vi.fn()
const mockUseAuth = vi.fn()
const mockUseAppConfig = vi.fn()

vi.mock('@/api/projects', () => ({
  projectApi: {
    update: (...args: unknown[]) => mockUpdate(...args),
    delete: vi.fn(),
    rotateApiKey: vi.fn(),
  },
}))
vi.mock('@/hooks/queries/use-system', () => ({ useAppConfig: () => mockUseAppConfig() }))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => mockUseTeams() }))
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
  useGitLabInstances: () => mockUseGitLabInstances(),
  useGitHubInstances: () => mockUseGitHubInstances(),
}))
vi.mock('@/context/useAuth', () => ({ useAuth: () => mockUseAuth() }))
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

beforeEach(() => {
  mockUseAuth.mockReturnValue({ permissions: [] })
  mockUseGitLabInstances.mockReturnValue({ data: { items: [] } })
  mockUseAppConfig.mockReturnValue({ data: undefined })
})

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
          token_configured: hasToken,
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
    mockUseTeams.mockReturnValue({ data: [] })
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

  it('lets an already-enabled project turn decoration off after the instance loses its token', async () => {
    mockUseGitHubInstances.mockReturnValue(githubInstances(false))

    renderSettings(githubProject({ github_pr_comments_enabled: true }))

    const toggle = screen.getByLabelText('Pull Request Decoration')
    expect(toggle).toBeEnabled()
    expect(toggle).toBeChecked()

    fireEvent.click(toggle)
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: false })
  })

  // active_only filtering hides a deactivated instance, which must not silently mask the stored value.
  it('shows the stored value when the linked instance is missing from the active list', async () => {
    mockUseGitHubInstances.mockReturnValue({ data: { items: [] } })

    renderSettings(githubProject({ github_pr_comments_enabled: true }))

    expect(screen.getByLabelText('Pull Request Decoration')).toBeChecked()

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: true })
  })

  it('shows nothing for a GitLab-sourced project', () => {
    renderSettings(githubProject({ github_instance_id: undefined, gitlab_instance_id: 'gl-1' }))

    expect(screen.queryByLabelText('Pull Request Decoration')).toBeNull()
  })
})

describe('ProjectSettings team ownership', () => {
  beforeEach(() => {
    mockUpdate.mockClear()
    mockUseTeams.mockReturnValue({
      data: [
        { id: 't1', name: 'Payments', members: [] },
        { id: 't2', name: 'Platform', members: [] },
      ],
    })
    mockUseGitHubInstances.mockReturnValue(githubInstances(true))
  })

  it('saves the picked teams with the rest of the form', async () => {
    renderSettings(githubProject({ team_ids: ['t1'], team_sources: { t1: 'gitlab:gl-1' } }))

    fireEvent.click(screen.getByRole('combobox', { name: 'Teams' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Platform' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1].team_ids).toEqual(['t1', 't2'])
  })

  it('names the teams it holds on the closed control', () => {
    renderSettings(githubProject({ team_ids: ['t1', 't2'], team_sources: { t1: 'gitlab:gl-1', t2: 'manual' } }))

    expect(screen.getByRole('combobox', { name: 'Teams' })).toHaveTextContent('Payments, Platform')
    expect(screen.queryByText('Owning Teams')).toBeNull()
  })

  it('deselects a team the project holds, whichever sync established it', async () => {
    renderSettings(githubProject({ team_ids: ['t1', 't2'], team_sources: { t1: 'gitlab:gl-1', t2: 'manual' } }))

    fireEvent.click(screen.getByRole('combobox', { name: 'Teams' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Payments' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1].team_ids).toEqual(['t2'])
  })

  it('says No Team when the project has no owner', () => {
    renderSettings(githubProject({ team_ids: [] }))

    expect(screen.getByRole('combobox', { name: 'Teams' })).toHaveTextContent('No Team')
  })

  // The teams list answers only the caller's own teams, so an owner outside them has no option
  // of its own — and a save stating the whole set would drop it without anyone choosing to.
  it('keeps an owner the caller cannot see selected and saves it back', async () => {
    renderSettings(githubProject({ team_ids: ['t1', 't9'], team_sources: { t9: 'github:gh-1' } }))

    expect(screen.getByRole('combobox', { name: 'Teams' })).toHaveTextContent('Payments, t9')

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1].team_ids).toEqual(['t1', 't9'])
  })
})

const GITLAB_INSTANCES = {
  data: {
    items: [
      {
        id: 'gl-1',
        name: 'Internal GitLab',
        url: 'https://gitlab.example.com',
        is_active: true,
        auto_create_projects: true,
        sync_teams: false,
        team_sync_depth: 1,
        created_at: '',
        created_by: 'a',
        token_configured: true,
      },
    ],
  },
}

function gitlabProject(overrides: Partial<Project> = {}): Project {
  return {
    id: 'p1',
    name: 'widget',
    members: [{ user_id: 'u1', role: 'admin' }],
    active_analyzers: [],
    gitlab_instance_id: 'gl-1',
    gitlab_project_id: 4242,
    gitlab_project_path: 'acme/widget',
    ...overrides,
  } as Project
}

describe('ProjectSettings GitLab binding', () => {
  beforeEach(() => {
    mockUpdate.mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
    mockUseGitHubInstances.mockReturnValue({ data: { items: [] } })
    // The instance list answers only system:manage.
    mockUseGitLabInstances.mockReturnValue({ data: undefined })
  })

  it('shows a project admin the binding without a way to edit it', () => {
    renderSettings(gitlabProject())

    expect(screen.getByText('GitLab Integration')).toBeInTheDocument()
    expect(screen.getByText('4242')).toBeInTheDocument()
    expect(screen.getByText('acme/widget')).toBeInTheDocument()
    expect(screen.queryByLabelText('GitLab Project ID')).toBeNull()
    expect(screen.queryByLabelText('GitLab Project Path (Optional)')).toBeNull()
  })

  it('saves the stored binding back unchanged for a project admin', async () => {
    renderSettings(gitlabProject())

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({
      gitlab_instance_id: 'gl-1',
      gitlab_project_id: 4242,
      gitlab_project_path: 'acme/widget',
    })
  })

  it('lets a project admin remove the binding', async () => {
    renderSettings(gitlabProject())

    fireEvent.click(screen.getByRole('button', { name: 'Remove GitLab link' }))
    expect(screen.getByText('The GitLab link is removed when you save.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({
      gitlab_instance_id: null,
      gitlab_project_id: null,
      gitlab_project_path: null,
    })
  })

  it('offers a project admin no way to bind an unbound project', () => {
    mockUseGitLabInstances.mockReturnValue(GITLAB_INSTANCES)

    renderSettings(
      gitlabProject({ gitlab_instance_id: undefined, gitlab_project_id: undefined, gitlab_project_path: undefined }),
    )

    expect(screen.queryByText('GitLab Integration')).toBeNull()
  })

  it('lets a system manager change the bound project id', async () => {
    mockUseAuth.mockReturnValue({ permissions: ['system:manage'] })
    mockUseGitLabInstances.mockReturnValue(GITLAB_INSTANCES)

    renderSettings(gitlabProject())

    const projectIdInput = screen.getByLabelText('GitLab Project ID')
    expect(projectIdInput).toHaveValue(4242)
    fireEvent.change(projectIdInput, { target: { value: '5151' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ gitlab_instance_id: 'gl-1', gitlab_project_id: 5151 })
  })

  it('clears the whole binding when a system manager picks no instance', async () => {
    mockUseAuth.mockReturnValue({ permissions: ['system:manage'] })
    mockUseGitLabInstances.mockReturnValue(GITLAB_INSTANCES)

    renderSettings(gitlabProject())

    fireEvent.click(screen.getByLabelText('GitLab Instance'))
    fireEvent.click(screen.getByRole('option', { name: 'None (Auto-detect from OIDC)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({
      gitlab_instance_id: null,
      gitlab_project_id: null,
      gitlab_project_path: null,
    })
  })
})

function appConfig(rescan: Pick<AppConfig, 'global_rescan_enabled' | 'global_rescan_interval'>): AppConfig {
  return {
    archive_enabled: false,
    project_limit_per_user: 0,
    retention_mode: 'project',
    global_retention_days: 90,
    global_retention_action: 'delete',
    rescan_mode: 'project',
    notifications: { email: false, slack: false, mattermost: false },
    default_project_analyzers: [],
    ...rescan,
  }
}

describe('ProjectSettings periodic re-scanning', () => {
  beforeEach(() => {
    mockUpdate.mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
    mockUseGitHubInstances.mockReturnValue(githubInstances(true))
  })

  it('shows the global schedule a project without its own inherits, and saves it still inheriting', async () => {
    mockUseAppConfig.mockReturnValue({ data: appConfig({ global_rescan_enabled: true, global_rescan_interval: 12 }) })
    renderSettings(githubProject())

    expect(screen.getByLabelText('Enable Re-scanning')).toBeChecked()
    expect(screen.getByLabelText('Interval (Hours)')).toHaveValue(12)

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1].rescan_enabled).toBeUndefined()
    expect(mockUpdate.mock.calls[0][1].rescan_interval).toBeUndefined()
  })

  it("shows a project's own schedule over the global one", () => {
    mockUseAppConfig.mockReturnValue({ data: appConfig({ global_rescan_enabled: false, global_rescan_interval: 12 }) })
    renderSettings(githubProject({ rescan_enabled: true, rescan_interval: 48 }))

    expect(screen.getByLabelText('Enable Re-scanning')).toBeChecked()
    expect(screen.getByLabelText('Interval (Hours)')).toHaveValue(48)
  })

  it("shows a project's own opt-out over a globally enabled schedule", () => {
    mockUseAppConfig.mockReturnValue({ data: appConfig({ global_rescan_enabled: true, global_rescan_interval: 12 }) })
    renderSettings(githubProject({ rescan_enabled: false }))

    expect(screen.getByLabelText('Enable Re-scanning')).not.toBeChecked()
  })
})
