import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { CreateProjectDialog } from '../CreateProjectDialog'

const mockMutate = vi.fn()

vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: { retention_mode: 'project', default_project_analyzers: ['trivy', 'epss_kev'] } }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-projects', () => ({
  useCreateProject: () => ({ mutate: mockMutate, isPending: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

beforeEach(() => {
  mockMutate.mockReset()
})

describe('CreateProjectDialog', () => {
  it('creates the project with the backend default analyzers when the user keeps them', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    fireEvent.change(screen.getByLabelText('Project Name'), { target: { value: 'svc' } })
    fireEvent.click(screen.getByRole('button', { name: /create project/i }))

    expect(mockMutate).toHaveBeenCalledTimes(1)
    expect(mockMutate.mock.calls[0][0].active_analyzers).toEqual(['trivy', 'epss_kev'])
  })
})
