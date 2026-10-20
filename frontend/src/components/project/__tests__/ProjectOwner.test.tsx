import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { githubInstancesApi } from '@/api/github-instances'
import { gitlabInstancesApi } from '@/api/gitlab-instances'
import type { Project } from '@/types/project'

import { ProjectOwner } from '../ProjectOwner'

const auth = vi.hoisted(() => ({ permissions: [] as string[] }))

vi.mock('@/api/gitlab-instances', () => ({ gitlabInstancesApi: { list: vi.fn() } }))
vi.mock('@/api/github-instances', () => ({ githubInstancesApi: { list: vi.fn() } }))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: (p: string) => auth.permissions.includes(p) }) }))

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, size: 100, pages: 1 })

// CI auto-creation names a project after its repository path, so namesakes of one path differ only by instance.
function ciProject(id: string, instanceId: string, gitlabProjectId: number, team = 'Payments'): Project {
  return {
    id,
    name: 'aufstrg/tm/app',
    gitlab_project_path: 'aufstrg/tm/app',
    gitlab_instance_id: instanceId,
    gitlab_project_id: gitlabProjectId,
    teams: [{ id: `t-${team}`, name: team }],
  }
}

function renderOwners(namesakes: Project[]) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      {namesakes.map((project) => (
        <div key={project.id} data-testid={project.id} className="flex">
          <ProjectOwner project={project} namesakes={namesakes} />
        </div>
      ))}
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  auth.permissions = []
  vi.mocked(gitlabInstancesApi.list).mockResolvedValue(
    page([{ id: 'gl-prod', name: 'Prod GitLab' }, { id: 'gl-dev', name: 'Dev GitLab' }]) as never,
  )
  vi.mocked(githubInstancesApi.list).mockResolvedValue(page([]) as never)
})

describe('ProjectOwner', () => {
  it('tells CI-created namesakes of one team apart by their GitLab instance, for a viewer who may list instances', async () => {
    auth.permissions = ['system:manage']
    renderOwners([ciProject('p1', 'gl-prod', 11), ciProject('p2', 'gl-dev', 22)])

    expect(await screen.findByText('GitLab · Prod GitLab')).toBeInTheDocument()
    expect(screen.getByText('GitLab · Dev GitLab')).toBeInTheDocument()
    expect(screen.queryByText('Payments')).not.toBeInTheDocument()
    expect(screen.queryByText('aufstrg/tm/app')).not.toBeInTheDocument()
  })

  it('tells them apart by their GitLab project for a viewer who may not list instances', () => {
    renderOwners([ciProject('p1', 'gl-prod', 11), ciProject('p2', 'gl-dev', 22)])

    expect(screen.getByText('GitLab project 11')).toBeInTheDocument()
    expect(screen.getByText('GitLab project 22')).toBeInTheDocument()
    expect(gitlabInstancesApi.list).not.toHaveBeenCalled()
  })

  it('names the owning teams when they differ, even where the instances differ too', () => {
    renderOwners([ciProject('p1', 'gl-prod', 11, 'Payments'), ciProject('p2', 'gl-dev', 22, 'Platform')])

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('Platform')).toBeInTheDocument()
    expect(screen.queryByText(/GitLab project/)).not.toBeInTheDocument()
  })

  it('names the repository path of unowned namesakes whose paths differ, capped like an owner so the name keeps its room', () => {
    renderOwners([
      { id: 'p1', name: 'app', teams: [], gitlab_project_path: 'a-very-long-group/with/a-deeply-nested/app' },
      { id: 'p2', name: 'app', teams: [], github_repository_path: 'org-b/app' },
    ])

    const path = screen.getByText('a-very-long-group/with/a-deeply-nested/app')
    expect(path).toHaveClass('truncate', 'font-mono')
    expect(path.parentElement).toHaveClass('min-w-0', 'max-w-[50%]')
  })
})
