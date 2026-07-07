import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { Project, ProjectsResponse } from '@/types/project'

// Mock the query hooks so we can drive the list vs. the resolved-selection paths
// independently, reproducing the "selected project not on current page" scenario.
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

  it('shows the selected project name even when it is not on the current list page', () => {
    // Current (unfiltered first page) does NOT contain the selected project p2.
    vi.mocked(useProjects).mockReturnValue(
      asListResult(mkListResponse([mkProject('p1', 'Alpha'), mkProject('p3', 'Gamma')])),
    )
    // The selected project is resolved independently by useProject(value).
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
    // The clear affordance must NOT be a nested <button> element.
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
})
