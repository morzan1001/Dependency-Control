import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'

import ProjectsPage from '../Projects'
import type { Project } from '@/types/project'

const VISIBLE_PROJECTS = 5

const { useProjectsMock } = vi.hoisted(() => ({ useProjectsMock: vi.fn() }))
vi.mock('@/hooks/queries/use-projects', () => ({ useProjects: (...args: unknown[]) => useProjectsMock(...args) }))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-instances', () => ({ useInstanceNames: () => new Map() }))
vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: { project_limit_per_user: 1 } }),
}))
vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ hasPermission: (permission: string) => permission === 'project:create' }),
}))
vi.mock('@/components/project/CreateProjectDialog', () => ({ CreateProjectDialog: () => null }))

function renderProjects(pages = 1, items: Project[] = []) {
  useProjectsMock.mockReturnValue({
    data: { items, total: VISIBLE_PROJECTS, page: 1, size: 12, pages },
    isLoading: false,
    error: null,
  })
  render(
    <MemoryRouter>
      <ProjectsPage />
    </MemoryRouter>,
  )
}

beforeEach(() => useProjectsMock.mockReset())

describe('ProjectsPage New Project button', () => {
  it('stays enabled however many projects the user can see, since the server counts the ones the user administers', () => {
    renderProjects()

    expect(screen.getByRole('button', { name: /New Project/i })).toBeEnabled()
  })
})

describe('ProjectsPage sorting', () => {
  const lastPage = () => useProjectsMock.mock.calls[useProjectsMock.mock.calls.length - 1][1]

  function onPageTwo() {
    renderProjects(3)
    fireEvent.click(screen.getByRole('button', { name: /Next/ }))
    expect(lastPage()).toBe(2)
  }

  it('returns to the first page when the sort field changes, like the team filter', async () => {
    onPageTwo()

    fireEvent.keyDown(screen.getByRole('combobox'), { key: 'Enter' })
    fireEvent.click(await screen.findByRole('option', { name: 'Name' }))

    expect(useProjectsMock.mock.calls[useProjectsMock.mock.calls.length - 1][3]).toBe('name')
    expect(lastPage()).toBe(1)
  })

  it('returns to the first page when the sort order flips', () => {
    onPageTwo()

    fireEvent.click(screen.getByRole('button', { name: 'Sort ascending' }))

    expect(useProjectsMock.mock.calls[useProjectsMock.mock.calls.length - 1][4]).toBe('asc')
    expect(lastPage()).toBe(1)
  })

  it('names the icon-only sort order button by the order a click gives', () => {
    renderProjects()

    fireEvent.click(screen.getByRole('button', { name: 'Sort ascending' }))

    expect(screen.getByRole('button', { name: 'Sort descending' })).toBeInTheDocument()
  })
})

describe('ProjectsPage header on a tablet', () => {
  it('wraps its search, filters and New Project onto further lines from sm on instead of running past the screen', () => {
    renderProjects()

    const controls = screen.getByRole('button', { name: /New Project/i }).parentElement
    expect(controls).toHaveClass('flex-col', 'sm:flex-row', 'sm:flex-wrap')
  })
})

describe('ProjectsPage namesakes', () => {
  it('names the owner of each project whose name another card shares, as the project picker does, and only theirs', () => {
    renderProjects(1, [
      { id: 'p1', name: 'shared-lib', teams: [{ id: 't1', name: 'Payments' }] },
      { id: 'p2', name: 'shared-lib', teams: [], gitlab_project_path: 'platform/shared-lib' },
      { id: 'p3', name: 'checkout', teams: [{ id: 't3', name: 'Retail' }] },
    ])

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('platform/shared-lib')).toBeInTheDocument()
    expect(screen.queryByText('Retail')).not.toBeInTheDocument()
  })

  it('spans the card title up to the icon, so an owner tag wider than the name keeps its text up to half the row', () => {
    renderProjects(1, [
      { id: 'p1', name: 'api', teams: [{ id: 't1', name: 'Platform Engineering' }] },
      { id: 'p2', name: 'api', teams: [{ id: 't2', name: 'Payments' }] },
    ])

    expect(screen.getByText('Platform Engineering').closest('.max-w-\\[50\\%\\]')?.parentElement).toHaveClass('flex-1')
  })
})

describe('ProjectsPage analyzer pills', () => {
  it('outlines a scanner pill like every neutral badge and edges a post-processor pill in its own blue', () => {
    renderProjects(1, [{ id: 'p1', name: 'checkout', teams: [], active_analyzers: ['trivy', 'epss_kev'] } as Project])

    const scanner = screen.getByText('Trivy (Container/FS)')
    const postProcessor = screen.getByText('EPSS/KEV Enrichment')
    expect(scanner).toHaveClass('border-foreground/45')
    expect(scanner).not.toHaveClass('border-transparent')
    expect(postProcessor).toHaveClass('border-blue-200', 'dark:border-blue-800', 'bg-blue-100')
    expect(postProcessor).not.toHaveClass('border-foreground/45')
  })
})

describe('ProjectsPage accessible names', () => {
  it('names its search box and sort dropdown, which have no visible label', () => {
    renderProjects()

    expect(screen.getByRole('textbox', { name: 'Search projects' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Sort by' })).toBeInTheDocument()
  })
})
