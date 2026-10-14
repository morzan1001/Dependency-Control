import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { toast } from 'sonner'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { ProjectSettings } from '../ProjectSettings'
import { NOTIFICATION_EVENTS } from '@/lib/constants'
import { createMutationCache } from '@/lib/mutation-cache'
import type { Project } from '@/types/project'
import type { AppConfig } from '@/types/system'
import type { User } from '@/types/user'

const mockUpdate = vi.fn().mockResolvedValue({})
const mockDelete = vi.fn()
const mockRotateApiKey = vi.fn()
const mockGitHubList = vi.fn()
const mockGitLabList = vi.fn()
const mockUseTeams = vi.fn()
const mockUseAuth = vi.fn()
const mockUseAppConfig = vi.fn()
const mockUseNotificationChannels = vi.fn()
const mockUseProjectBranches = vi.fn()
const mockUpdateNotifications = vi.fn()
const mockUseUpdateProjectNotifications = vi.fn()

vi.mock('@/api/projects', () => ({
  projectApi: {
    update: (...args: unknown[]) => mockUpdate(...args),
    delete: (...args: unknown[]) => mockDelete(...args),
    rotateApiKey: (...args: unknown[]) => mockRotateApiKey(...args),
  },
}))
vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => mockUseAppConfig(),
  useNotificationChannels: () => mockUseNotificationChannels(),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => mockUseTeams() }))
vi.mock('@/hooks/queries/use-projects', () => ({
  projectKeys: { detail: (id: string) => ['project', id] },
  useProjectBranches: () => mockUseProjectBranches(),
  useUpdateProjectNotifications: (meta: unknown) => {
    mockUseUpdateProjectNotifications(meta)
    return { mutate: mockUpdateNotifications, isPending: false }
  },
}))
vi.mock('@/hooks/queries/use-webhooks', () => ({
  useProjectWebhooks: () => ({ data: [], isLoading: false }),
  useCreateProjectWebhook: () => ({ mutateAsync: vi.fn() }),
  useUpdateWebhook: () => ({ mutateAsync: vi.fn() }),
  useDeleteWebhook: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/api/gitlab-instances', () => ({
  gitlabInstancesApi: { list: (...args: unknown[]) => mockGitLabList(...args) },
}))
vi.mock('@/api/github-instances', () => ({
  githubInstancesApi: { list: (...args: unknown[]) => mockGitHubList(...args) },
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
  // The instance lists answer only system:manage.
  mockGitLabList.mockReset().mockRejectedValue(new Error('Request failed with status code 403'))
  mockGitHubList.mockReset().mockRejectedValue(new Error('Request failed with status code 403'))
  mockUseAppConfig.mockReturnValue({ data: undefined })
  mockUseNotificationChannels.mockReturnValue(undefined)
  mockUseProjectBranches.mockReturnValue({ data: [] })
})

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
  const queryClient = new QueryClient({ mutationCache: createMutationCache(), defaultOptions: { queries: { retry: false } } })
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
  })

  it('lets a project admin without system:manage switch decoration on', async () => {
    renderSettings(githubProject())

    fireEvent.click(screen.getByLabelText('Pull Request Decoration'))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: true })
    expect(mockGitHubList).not.toHaveBeenCalled()
  })

  it('round-trips an already-enabled project', async () => {
    renderSettings(githubProject({ github_pr_comments_enabled: true }))

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: true })
  })

  it('turns decoration off', async () => {
    renderSettings(githubProject({ github_pr_comments_enabled: true }))

    fireEvent.click(screen.getByLabelText('Pull Request Decoration'))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ github_pr_comments_enabled: false })
  })

  it('shows nothing for a GitLab-sourced project', () => {
    renderSettings(githubProject({ github_instance_id: undefined, gitlab_instance_id: 'gl-1' }))

    expect(screen.queryByLabelText('Pull Request Decoration')).toBeNull()
  })
})

describe('ProjectSettings default branch', () => {
  beforeEach(() => {
    mockUpdate.mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
    mockUseProjectBranches.mockReturnValue({ data: [{ name: 'main' }, { name: 'dev' }] })
  })

  it('clears the stored default branch when None is picked', async () => {
    renderSettings(githubProject({ default_branch: 'main' }))

    fireEvent.click(screen.getByLabelText('Default Branch'))
    fireEvent.click(screen.getByRole('option', { name: 'None (Show All)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    const wire = JSON.parse(JSON.stringify(mockUpdate.mock.calls[0][1]))
    expect(wire).toHaveProperty('default_branch', null)
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

function gitlabInstances(tokenConfigured = true) {
  return {
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
        token_configured: tokenConfigured,
      },
    ],
  }
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

  it('lets a project admin without system:manage switch MR decoration on', async () => {
    renderSettings(gitlabProject())

    fireEvent.click(screen.getByLabelText('Merge Request Decoration'))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ gitlab_mr_comments_enabled: true })
    expect(mockGitLabList).not.toHaveBeenCalled()
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
    mockGitLabList.mockResolvedValue(gitlabInstances())

    renderSettings(
      gitlabProject({ gitlab_instance_id: undefined, gitlab_project_id: undefined, gitlab_project_path: undefined }),
    )

    expect(screen.queryByText('GitLab Integration')).toBeNull()
  })

  it('lets a system manager change the bound project id', async () => {
    mockUseAuth.mockReturnValue({ permissions: ['system:manage'] })
    mockGitLabList.mockResolvedValue(gitlabInstances())

    renderSettings(gitlabProject())

    const projectIdInput = await screen.findByLabelText('GitLab Project ID')
    expect(projectIdInput).toHaveValue(4242)
    fireEvent.change(projectIdInput, { target: { value: '5151' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ gitlab_instance_id: 'gl-1', gitlab_project_id: 5151 })
  })

  it('clears the whole binding when a system manager picks no instance', async () => {
    mockUseAuth.mockReturnValue({ permissions: ['system:manage'] })
    mockGitLabList.mockResolvedValue(gitlabInstances())

    renderSettings(gitlabProject())

    fireEvent.click(await screen.findByLabelText('GitLab Instance'))
    fireEvent.click(screen.getByRole('option', { name: 'None (Auto-detect from OIDC)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({
      gitlab_instance_id: null,
      gitlab_project_id: null,
      gitlab_project_path: null,
    })
  })

  // A stored true on a tokenless instance makes every save a 400 until it is switched off.
  it('lets a system manager turn MR decoration off after the instance loses its token', async () => {
    mockUseAuth.mockReturnValue({ permissions: ['system:manage'] })
    mockGitLabList.mockResolvedValue(gitlabInstances(false))

    renderSettings(gitlabProject({ gitlab_mr_comments_enabled: true }))

    await screen.findByLabelText('GitLab Project ID')
    const toggle = screen.getByLabelText('Merge Request Decoration')
    expect(toggle).toBeChecked()
    fireEvent.click(toggle)
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ gitlab_mr_comments_enabled: false })
  })
})

function appConfig(rescan: Pick<AppConfig, 'global_rescan_enabled' | 'global_rescan_interval'>): AppConfig {
  return {
    archive_enabled: false,
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

describe('ProjectSettings API key rotation', () => {
  const writeText = vi.fn()

  beforeEach(() => {
    vi.mocked(toast.success).mockClear()
    vi.mocked(toast.error).mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
    mockRotateApiKey.mockResolvedValue({ project_id: 'p1', api_key: 'dc_rotated_key', note: '' })
    // jsdom ships no Clipboard API.
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
  })

  async function rotateAndCopyKey() {
    renderSettings(githubProject())
    fireEvent.click(screen.getByRole('button', { name: 'Rotate Key' }))
    fireEvent.click(within(screen.getByRole('dialog', { name: 'Rotate API Key' })).getByRole('button', { name: 'Rotate Key' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Copy API key' }))
  }

  it('asks before rotating, like the deletion, and names the project in bold', async () => {
    renderSettings(githubProject())

    fireEvent.click(screen.getByRole('button', { name: 'Rotate Key' }))

    const dialog = screen.getByRole('dialog', { name: 'Rotate API Key' })
    expect(within(dialog).getByText('acme/widget', { selector: 'strong' })).toBeInTheDocument()
    expect(mockRotateApiKey).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(mockRotateApiKey).not.toHaveBeenCalled()
  })

  it('confirms the copy once the clipboard holds the new key', async () => {
    writeText.mockResolvedValue(undefined)

    await rotateAndCopyKey()

    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('API key copied to clipboard'))
    expect(writeText.mock.calls).toEqual([['dc_rotated_key']])
    expect(screen.getByRole('button', { name: 'Copy API key' }).querySelector('.lucide-check')).toBeInTheDocument()
  })

  it('tells the admin to copy the new key by hand when the clipboard refuses', async () => {
    writeText.mockRejectedValue(new Error('denied'))

    await rotateAndCopyKey()

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Could not reach the clipboard', {
        description: expect.stringMatching(/copy it by hand/i),
      }),
    )
    expect(toast.success).not.toHaveBeenCalledWith(expect.stringMatching(/copied/i))
    expect(screen.getByRole('button', { name: 'Copy API key' }).querySelector('.lucide-check')).not.toBeInTheDocument()
  })
})

describe('ProjectSettings failures', () => {
  beforeEach(() => {
    vi.mocked(toast.error).mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
  })

  it('names a save that failed and why', async () => {
    mockUpdate.mockRejectedValueOnce(new Error('Network Error'))
    renderSettings(githubProject())

    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to update project', { description: 'Network Error' }))
  })

  it('names a deletion that failed and why', async () => {
    mockDelete.mockRejectedValueOnce(new Error('Network Error'))
    renderSettings(githubProject())

    fireEvent.click(screen.getByRole('button', { name: 'Delete Project' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete Project' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to delete project', { description: 'Network Error' }))
  })

  it('names a key rotation that failed and why', async () => {
    mockRotateApiKey.mockRejectedValueOnce(new Error('Network Error'))
    renderSettings(githubProject())

    fireEvent.click(screen.getByRole('button', { name: 'Rotate Key' }))
    fireEvent.click(within(screen.getByRole('dialog', { name: 'Rotate API Key' })).getByRole('button', { name: 'Rotate Key' }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to rotate API key', { description: 'Network Error' }))
  })

  it('names a failed notification settings save, which the error toast completes with the reason', () => {
    renderSettings(githubProject())

    expect(mockUseUpdateProjectNotifications).toHaveBeenCalledWith({ errorTitle: 'Failed to update notification settings' })
  })
})

describe('ProjectSettings data retention', () => {
  beforeEach(() => {
    mockUpdate.mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
  })

  it('saves the retention period and action the project sets', async () => {
    mockUseAppConfig.mockReturnValue({ data: appConfig({ global_rescan_enabled: false, global_rescan_interval: 24 }) })
    renderSettings(githubProject({ retention_days: 90, retention_action: 'delete' }))

    fireEvent.change(screen.getByLabelText('Retention Period (Days)'), { target: { value: '30' } })
    fireEvent.click(screen.getByLabelText('Retention Action'))
    fireEvent.click(screen.getByRole('option', { name: 'None (Keep Forever)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    await waitFor(() => expect(mockUpdate).toHaveBeenCalled())
    expect(mockUpdate.mock.calls[0][1]).toMatchObject({ retention_days: 30, retention_action: 'none' })
  })

  it('names the global retention and re-scan schedule a project cannot change', () => {
    mockUseAppConfig.mockReturnValue({
      data: {
        ...appConfig({ global_rescan_enabled: true, global_rescan_interval: 12 }),
        archive_enabled: true,
        retention_mode: 'global',
        global_retention_days: 30,
        global_retention_action: 'archive',
        rescan_mode: 'global',
      },
    })
    renderSettings(githubProject())

    expect(screen.getByText('Data is retained for 30 days (archived to S3).')).toBeInTheDocument()
    expect(screen.getByText('Re-scanning is enabled (every 12 hours).')).toBeInTheDocument()
    expect(screen.queryByLabelText('Retention Period (Days)')).toBeNull()
  })
})

describe('ProjectSettings notifications', () => {
  beforeEach(() => {
    mockUpdateNotifications.mockClear()
    mockUseTeams.mockReturnValue({ data: [] })
    mockUseNotificationChannels.mockReturnValue(['email'])
  })

  it('names each checkbox by its event and channel', () => {
    renderSettings(githubProject())

    expect(screen.getByRole('checkbox', { name: 'Analysis Completed: Email' })).not.toBeChecked()
  })

  it('stores a matrix with nothing checked as a mute of every event rather than as no override', () => {
    renderSettings(githubProject({
      members: [{ user_id: 'u1', role: 'admin', notification_preferences: { analysis_completed: ['email'] } }],
    }))

    fireEvent.click(screen.getByRole('checkbox', { name: 'Analysis Completed: Email' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Notification Settings' }))

    expect(mockUpdateNotifications.mock.calls[0][0].settings.notification_preferences).toEqual(
      Object.fromEntries(NOTIFICATION_EVENTS.map((event) => [event.id, []])),
    )
  })

  it('keeps the checked channels of the events it names', () => {
    renderSettings(githubProject())

    fireEvent.click(screen.getByRole('checkbox', { name: 'Vulnerability Found: Email' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save Notification Settings' }))

    expect(mockUpdateNotifications.mock.calls[0][0].settings.notification_preferences).toMatchObject({
      vulnerability_found: ['email'],
      analysis_completed: [],
    })
  })
})
