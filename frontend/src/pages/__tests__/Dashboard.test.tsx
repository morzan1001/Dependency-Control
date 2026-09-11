import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Dashboard from '../Dashboard'
import type { Project } from '@/types/project'

const { useProjectsMock } = vi.hoisted(() => ({ useProjectsMock: vi.fn() }))

vi.mock('@/hooks/queries/use-projects', () => ({ useProjects: () => useProjectsMock() }))
vi.mock('@/hooks/queries/use-analytics', () => ({
  useDashboardStats: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/hooks/queries/use-scans', () => ({
  useRecentScans: () => ({ data: [], isLoading: false }),
}))
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }))
vi.mock('recharts', () => ({
  ResponsiveContainer: () => null,
  BarChart: () => null,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
}))

// jsdom gives every element zero height, so the real virtualizer would render no rows at all.
vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({ index, key: index, start: index * 73, end: (index + 1) * 73 })),
    getTotalSize: () => count * 73,
    measureElement: () => undefined,
  }),
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
