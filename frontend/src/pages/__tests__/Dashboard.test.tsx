import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Dashboard from '../Dashboard'
import type { Project } from '@/types/project'

const { useProjectsMock, navigateMock } = vi.hoisted(() => ({ useProjectsMock: vi.fn(), navigateMock: vi.fn() }))

vi.mock('@/hooks/queries/use-projects', () => ({ useProjects: () => useProjectsMock() }))
vi.mock('@/hooks/queries/use-analytics', () => ({
  useDashboardStats: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/hooks/queries/use-scans', () => ({
  useRecentScans: () => ({ data: [], isLoading: false }),
}))
vi.mock('react-router-dom', () => ({ useNavigate: () => navigateMock }))
vi.mock('recharts', () => ({
  ResponsiveContainer: () => null,
  BarChart: () => null,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
}))

function project(id: string, teams: Project['teams']): Project {
  return { id, name: `project-${id}`, teams } as Project
}

function renderDashboard(projects: Project[]) {
  useProjectsMock.mockReturnValue({
    data: { items: projects, total: projects.length, page: 1, size: 50, pages: 1 },
    isLoading: false,
  })
  return render(<Dashboard />)
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('Dashboard project table team column', () => {
  it('tells the reader a four-owner project has three more owners than the cell shows', () => {
    renderDashboard([
      project('p1', [
        { id: 't1', name: 'Payments' },
        { id: 't2', name: 'Platform' },
        { id: 't3', name: 'Identity' },
        { id: 't4', name: 'Data' },
      ]),
    ])

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('+3')).toBeInTheDocument()
    expect(screen.getByTitle('Payments, Platform, Identity, Data')).toBeInTheDocument()
  })

  it('renders a project no team owns without breaking on the empty list', () => {
    renderDashboard([project('p1', [])])

    expect(screen.getByText('project-p1')).toBeInTheDocument()
    expect(screen.getByText('Unassigned')).toBeInTheDocument()
  })
})

describe('Dashboard severity cards', () => {
  it.each([
    ['Critical Vulnerabilities', 'CRITICAL'],
    ['High Vulnerabilities', 'HIGH'],
  ])('open the vulnerability search filtered by severity from %s', (title, severity) => {
    renderDashboard([])

    fireEvent.click(screen.getByText(title))

    expect(navigateMock).toHaveBeenCalledWith(`/analytics?tab=search-vulns&severity=${severity}`)
  })
})

describe('Dashboard project table rows', () => {
  it('renders every project of the page with its risk status and opens it on click', () => {
    renderDashboard([
      { ...project('p1', []), stats: { critical: 2, high: 1 } } as Project,
      { ...project('p2', []), stats: { critical: 0, high: 4 } } as Project,
      { ...project('p3', []), stats: { critical: 0, high: 0 } } as Project,
    ])

    const statuses = ['p1', 'p2', 'p3'].map((id) =>
      within(screen.getByRole('row', { name: new RegExp(`project-${id}`) })).getByText(/Critical|High Risk|Secure/).textContent,
    )
    expect(statuses).toEqual(['Critical', 'High Risk', 'Secure'])

    fireEvent.click(screen.getByText('project-p2'))
    expect(navigateMock).toHaveBeenCalledWith('/projects/p2')
  })
})

