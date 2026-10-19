import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { Project, ProjectsResponse } from '@/types/project'

// Mock the query hooks to drive the list and resolved-selection paths independently.
vi.mock('@/hooks/queries/use-projects', () => ({
  useProjects: vi.fn(),
  useProject: vi.fn(),
}))

import { useProjects, useProject } from '@/hooks/queries/use-projects'
import { ProjectCombobox } from '../project-combobox'

const mkProject = (id: string, name: string): Project => ({ id, name })

const mkListResponse = (items: Project[]): ProjectsResponse => ({
  items,
  total: items.length,
  page: 1,
  size: 50,
  pages: 1,
})

const asListResult = (data: ProjectsResponse | undefined, isLoading = false) =>
  ({ data, isLoading }) as unknown as ReturnType<typeof useProjects>

const asDetailResult = (data: Project | undefined) =>
  ({ data }) as unknown as ReturnType<typeof useProject>

describe('ProjectCombobox', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists the projects by name, like the team pickers, instead of newest first', () => {
    vi.mocked(useProjects).mockReturnValue(asListResult(mkListResponse([])))
    vi.mocked(useProject).mockReturnValue(asDetailResult(undefined))

    render(<ProjectCombobox value="" onValueChange={vi.fn()} />)

    expect(useProjects).toHaveBeenCalledWith(undefined, 1, 50, 'name', 'asc')
  })

  it('shows the selected project name even when it is not on the current list page', () => {
    vi.mocked(useProjects).mockReturnValue(
      asListResult(mkListResponse([mkProject('p1', 'Alpha'), mkProject('p3', 'Gamma')])),
    )
    vi.mocked(useProject).mockReturnValue(asDetailResult(mkProject('p2', 'Beta Project')))

    render(<ProjectCombobox value="p2" onValueChange={vi.fn()} />)

    expect(screen.getByText('Beta Project')).toBeInTheDocument()
    expect(screen.queryByText('Select a project...')).not.toBeInTheDocument()
  })

  it('does not nest a <button> inside the trigger button (valid HTML) and clears via a role=button span', () => {
    vi.mocked(useProjects).mockReturnValue(asListResult(mkListResponse([mkProject('p2', 'Beta')])))
    vi.mocked(useProject).mockReturnValue(asDetailResult(mkProject('p2', 'Beta')))

    const onValueChange = vi.fn()
    render(<ProjectCombobox value="p2" onValueChange={onValueChange} />)

    const trigger = screen.getByRole('combobox')
    expect(trigger.querySelector('button')).toBeNull()

    const clear = screen.getByLabelText('Clear selection')
    expect(clear.tagName).toBe('SPAN')

    fireEvent.click(clear)
    expect(onValueChange).toHaveBeenCalledWith('')
  })

  it('clears via keyboard (Enter) on the clear affordance', () => {
    vi.mocked(useProjects).mockReturnValue(asListResult(mkListResponse([mkProject('p2', 'Beta')])))
    vi.mocked(useProject).mockReturnValue(asDetailResult(mkProject('p2', 'Beta')))

    const onValueChange = vi.fn()
    render(<ProjectCombobox value="p2" onValueChange={onValueChange} />)

    const clear = screen.getByLabelText('Clear selection')
    fireEvent.keyDown(clear, { key: 'Enter' })
    expect(onValueChange).toHaveBeenCalledWith('')
  })

  it('has an accessible name, like the other pickers', () => {
    vi.mocked(useProjects).mockReturnValue(asListResult(mkListResponse([])))
    vi.mocked(useProject).mockReturnValue(asDetailResult(undefined))

    render(<ProjectCombobox value="" onValueChange={vi.fn()} />)

    expect(screen.getByRole('combobox', { name: 'Project' })).toBeInTheDocument()
  })
})

describe('ProjectCombobox namesakes', () => {
  const inTeam = (id: string, name: string, team: string): Project => ({ id, name, teams: [{ id: `t-${id}`, name: team }] })

  function openWith(items: Project[], value = '') {
    vi.mocked(useProjects).mockReturnValue(asListResult(mkListResponse(items)))
    vi.mocked(useProject).mockReturnValue(asDetailResult(undefined))
    render(<ProjectCombobox value={value} onValueChange={vi.fn()} />)
    fireEvent.click(screen.getByRole('combobox'))
  }

  it('names the owning team of each project whose name another one shares, and only theirs', () => {
    openWith([inTeam('p1', 'aufstrg/tm/app', 'Payments'), inTeam('p2', 'aufstrg/tm/app', 'Platform'), inTeam('p3', 'checkout', 'Retail')])

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('Platform')).toBeInTheDocument()
    expect(screen.queryByText('Retail')).not.toBeInTheDocument()
  })

  it('names the repository path of a namesake no team owns', () => {
    openWith([
      { id: 'p1', name: 'app', teams: [], gitlab_project_path: 'group-a/app' },
      { id: 'p2', name: 'app', teams: [], github_repository_path: 'org-b/app' },
    ])

    expect(screen.getByText('group-a/app')).toBeInTheDocument()
    expect(screen.getByText('org-b/app')).toBeInTheDocument()
  })

  it('names the owner of the chosen namesake on the closed picker too', () => {
    vi.mocked(useProjects).mockReturnValue(
      asListResult(mkListResponse([inTeam('p1', 'app', 'Payments'), inTeam('p2', 'app', 'Platform')])),
    )
    vi.mocked(useProject).mockReturnValue(asDetailResult(undefined))

    render(<ProjectCombobox value="p2" onValueChange={vi.fn()} />)

    expect(screen.getByRole('combobox')).toHaveTextContent('Platform')
    expect(screen.queryByText('Payments')).not.toBeInTheDocument()
  })
})
