import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

import ProjectDetails from '../ProjectDetails'

const mockUseProject = vi.fn()
const mockUseProjectBranches = vi.fn()
const mockUseCurrentUser = vi.fn()

vi.mock('@/hooks/queries/use-projects', () => ({
  useProject: (...args: unknown[]) => mockUseProject(...args),
  useProjectBranches: (...args: unknown[]) => mockUseProjectBranches(...args),
}))

vi.mock('@/hooks/queries/use-users', () => ({
  useCurrentUser: (...args: unknown[]) => mockUseCurrentUser(...args),
}))

vi.mock('@/api/projects', () => ({
  projectApi: { exportCsv: vi.fn(), exportSbom: vi.fn() },
}))

// Render the resolved branch selection so the test can observe it.
vi.mock('@/components/project/ProjectOverview', () => ({
  ProjectOverview: ({ selectedBranches }: { selectedBranches: string[] }) => (
    <div data-testid="overview-branches">{selectedBranches.join(',')}</div>
  ),
}))
vi.mock('@/components/project/ProjectScans', () => ({ ProjectScans: () => null }))
vi.mock('@/components/project/ProjectWaivers', () => ({ ProjectWaivers: () => null }))
vi.mock('@/components/project/ProjectMembers', () => ({ ProjectMembers: () => null }))
vi.mock('@/components/project/ProjectSettings', () => ({ ProjectSettings: () => null }))
vi.mock('@/components/project/ProjectArchives', () => ({ ProjectArchives: () => null }))

function branch(name: string, { is_active = true, is_default = false } = {}) {
  return { name, is_active, is_default, last_scan_at: '2026-08-14T00:00:00Z' }
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/projects/p1']}>
      <Routes>
        <Route path="/projects/:id" element={<ProjectDetails />} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockUseCurrentUser.mockReturnValue({ data: undefined })
})

describe('ProjectDetails branch-filter initialization', () => {
  it('selects one branch even when the project has no default_branch (W8)', () => {
    // 530 of 656 production projects have no default_branch; the backend resolves one anyway.
    mockUseProject.mockReturnValue({ data: undefined, isLoading: true })
    mockUseProjectBranches.mockReturnValue({
      data: [branch('main'), branch('dev', { is_default: true }), branch('feature-x')],
      isSuccess: true,
    })

    const { rerender } = renderPage()

    expect(screen.queryByTestId('overview-branches')).toBeNull()

    mockUseProject.mockReturnValue({
      data: { id: 'p1', name: 'Proj', default_branch: undefined },
      isLoading: false,
    })
    rerender(
      <MemoryRouter initialEntries={['/projects/p1']}>
        <Routes>
          <Route path="/projects/:id" element={<ProjectDetails />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByTestId('overview-branches').textContent).toBe('dev')
  })

  it('preserves an intentionally empty selection when all branches are deselected', () => {
    mockUseProject.mockReturnValue({
      data: { id: 'p1', name: 'Proj', default_branch: 'main' },
      isLoading: false,
    })
    mockUseProjectBranches.mockReturnValue({
      data: [branch('main', { is_default: true }), branch('dev')],
      isSuccess: true,
    })

    renderPage()
    expect(screen.getByTestId('overview-branches').textContent).toBe('main')

    fireEvent.click(screen.getByRole('button', { name: /Filter Branches/i }))
    fireEvent.click(screen.getByLabelText('Select All Active'))
    expect(screen.getByTestId('overview-branches').textContent).toBe('main,dev')

    fireEvent.click(screen.getByLabelText('Select All Active'))

    // Selection must stay empty; the init guard must not snap it back.
    expect(screen.getByTestId('overview-branches').textContent).toBe('')
  })
})
