import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Dashboard from '../Dashboard'
import type { Project } from '@/types/project'

const { useProjectsMock, useProjectDetailsMock, navigateMock, useRecentScansMock } = vi.hoisted(() => ({
  useProjectsMock: vi.fn(),
  useProjectDetailsMock: vi.fn((_ids: readonly string[]): Project[] => []),
  navigateMock: vi.fn(),
  useRecentScansMock: vi.fn(() => ({ data: [] as unknown[], isLoading: false })),
}))

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjects: (...args: unknown[]) => useProjectsMock(...args),
  useProjectDetails: (ids: readonly string[]) => useProjectDetailsMock(ids),
}))
vi.mock('@/hooks/queries/use-instances', () => ({ useInstanceNames: () => new Map() }))
vi.mock('@/hooks/queries/use-analytics', () => ({
  useDashboardStats: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/hooks/queries/use-scans', () => ({
  useRecentScans: () => useRecentScansMock(),
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

describe('Dashboard recent activity', () => {
  it('breaks a long branch name anywhere, wraps the status under it when short of room and keeps the date whole', () => {
    const branch = 'feature/PAY-4821-checkout-redesign-with-a-considerably-longer-branch-name'
    useRecentScansMock.mockReturnValue({
      data: [{ id: 's1', project_id: 'p1', project_name: 'payments-service', pipeline_iid: 1039, branch, status: 'completed', created_at: '2026-10-13T13:31:00Z' }],
      isLoading: false,
    })
    renderDashboard([])

    const run = screen.getByText(`Pipeline #1039 on ${branch}`)
    const row = run.closest('.space-y-1')!.parentElement!
    expect(run).toHaveClass('wrap-anywhere')
    expect(run.parentElement).toHaveClass('flex-wrap')
    expect(row).toHaveClass('gap-4')
    expect(row.lastElementChild).toHaveClass('shrink-0')
  })
})

describe('Dashboard recent activity namesakes', () => {
  const scan = (id: string, projectId: string, projectName: string) => ({
    id, project_id: projectId, project_name: projectName, branch: 'main', status: 'completed', created_at: '2026-10-13T13:31:00Z',
  })
  const owners: Record<string, Project> = {
    p1: { id: 'p1', name: 'shared-lib', teams: [{ id: 't1', name: 'Payments' }] },
    p2: { id: 'p2', name: 'shared-lib', teams: [], github_repository_path: 'org/shared-lib' },
  }

  it('names the owner of each project whose name another project in the list shares, as the project picker does', () => {
    useProjectDetailsMock.mockImplementation((ids) => ids.map((id) => owners[id]))
    useRecentScansMock.mockReturnValue({
      data: [scan('s1', 'p1', 'shared-lib'), scan('s2', 'p2', 'shared-lib'), scan('s3', 'p3', 'checkout')],
      isLoading: false,
    })
    renderDashboard([])

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('org/shared-lib')).toBeInTheDocument()
    expect(useProjectDetailsMock).toHaveBeenCalledWith(['p1', 'p2'])
    expect(useProjectDetailsMock).not.toHaveBeenCalledWith(expect.arrayContaining(['p3']))
  })

  it('truncates a long name inside the card and sets the owner hint in normal weight, as the project picker does', () => {
    useProjectDetailsMock.mockImplementation((ids) => ids.map((id) => owners[id]))
    useRecentScansMock.mockReturnValue({
      data: [scan('s1', 'p1', 'shared-lib'), scan('s2', 'p2', 'shared-lib')],
      isLoading: false,
    })
    renderDashboard([])

    const [name] = screen.getAllByText('shared-lib')
    expect(name).toHaveClass('truncate', 'font-medium')
    expect(name.closest('.space-y-1')).toHaveClass('min-w-0')
    expect(screen.getByText('Payments').closest('.font-medium')).toBeNull()
  })

  it('spans the name column up to the date, so an owner tag wider than the name keeps its text up to half the row', () => {
    useProjectDetailsMock.mockImplementation((ids) => ids.map((id) => owners[id]))
    useRecentScansMock.mockReturnValue({
      data: [scan('s1', 'p1', 'shared-lib'), scan('s2', 'p2', 'shared-lib')],
      isLoading: false,
    })
    renderDashboard([])

    expect(screen.getByText('Payments').closest('.space-y-1')).toHaveClass('flex-1')
  })

  it('looks no owner up for two runs of the same project', () => {
    useRecentScansMock.mockReturnValue({
      data: [scan('s1', 'p1', 'shared-lib'), scan('s2', 'p1', 'shared-lib')],
      isLoading: false,
    })
    renderDashboard([])

    expect(useProjectDetailsMock).not.toHaveBeenCalled()
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


describe('Dashboard project table sorting', () => {
  const lastSort = () => useProjectsMock.mock.calls[useProjectsMock.mock.calls.length - 1].slice(3)

  it('lists the newest projects first, then sorts a clicked column descending and flips it', () => {
    renderDashboard([project('p1', [])])
    expect(lastSort()).toEqual(['created_at', 'desc'])

    fireEvent.click(screen.getByRole('columnheader', { name: 'Critical' }))
    expect(lastSort()).toEqual(['critical', 'desc'])

    fireEvent.click(screen.getByRole('columnheader', { name: 'Critical' }))
    expect(lastSort()).toEqual(['critical', 'asc'])
  })

  it('sorts the Name column ascending first', () => {
    renderDashboard([project('p1', [])])

    fireEvent.click(screen.getByRole('columnheader', { name: 'Name' }))

    expect(lastSort()).toEqual(['name', 'asc'])
  })

  it('returns to the first page when a column is sorted, like the other paged tables', () => {
    useProjectsMock.mockReturnValue({
      data: { items: [project('p1', [])], total: 120, page: 1, size: 50, pages: 3 },
      isLoading: false,
    })
    const lastPage = () => useProjectsMock.mock.calls[useProjectsMock.mock.calls.length - 1][1]
    render(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: /Next/ }))
    expect(lastPage()).toBe(2)

    fireEvent.click(screen.getByRole('columnheader', { name: 'Critical' }))

    expect(lastPage()).toBe(1)
    expect(lastSort()).toEqual(['critical', 'desc'])
  })
})

describe('Dashboard project table on a narrow screen', () => {
  it('keeps the Name column 200px wide and scrolls the table sideways until it fits, from xl on', () => {
    renderDashboard([project('p1', [])])

    const table = screen.getByRole('table')
    expect(table).toHaveClass('table-fixed', 'min-w-[820px]')
    expect(table.parentElement).toHaveClass('overflow-x-auto', 'xl:overflow-visible')
  })
})

describe('Dashboard riskiest projects and recent activity on a phone or tablet', () => {
  it('splits the row 4 to 3 only from lg on, so below it neither card spans columns the grid lacks', () => {
    renderDashboard([project('p1', [])])

    const riskiest = screen.getByText('Top 5 Riskiest Projects').closest('.bg-card')
    const activity = screen.getByText('Recent Activity').closest('.bg-card')
    expect(riskiest).toHaveClass('lg:col-span-4')
    expect(riskiest).not.toHaveClass('col-span-4')
    expect(activity).toHaveClass('lg:col-span-3')
    expect(activity).not.toHaveClass('col-span-3')
  })
})

describe('Dashboard critical colour', () => {
  it('draws the critical card icon, count cell and Critical pill from the severity token, as the high ones are', () => {
    renderDashboard([{ ...project('p1', []), stats: { critical: 3, high: 1 } } as Project])

    const card = screen.getByText('Critical Vulnerabilities').closest('.rounded-lg') as HTMLElement
    expect(card.querySelector('svg')).toHaveClass('text-severity-critical')
    const row = screen.getByRole('row', { name: /project-p1/ })
    expect(within(row).getByText('3')).toHaveClass('text-severity-critical')
    expect(within(row).getByText('Critical')).toHaveClass('bg-severity-critical', 'text-severity-critical-foreground')
  })
})
