import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { CreateProjectDialog } from '../CreateProjectDialog'

const mockMutate = vi.fn()
let appConfig: { retention_mode: string; default_project_analyzers: string[] } | undefined

vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: appConfig }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-projects', () => ({
  useCreateProject: () => ({ mutate: mockMutate, isPending: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

beforeEach(() => {
  mockMutate.mockReset()
  appConfig = { retention_mode: 'project', default_project_analyzers: ['trivy', 'epss_kev'] }
})

function submit() {
  fireEvent.change(screen.getByLabelText('Project Name'), { target: { value: 'svc' } })
  fireEvent.click(screen.getByRole('button', { name: /create project/i }))
  expect(mockMutate).toHaveBeenCalledTimes(1)
  return mockMutate.mock.calls[0][0]
}

describe('CreateProjectDialog', () => {
  it('leaves the analyzers to the server default when the user keeps them', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    expect(submit().active_analyzers).toBeUndefined()
  })

  it('leaves the analyzers to the server default when the app config has not loaded', () => {
    appConfig = undefined
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    expect(submit().active_analyzers).toBeUndefined()
  })

  it('sends the analyzers the user picked', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    fireEvent.click(screen.getByRole('checkbox', { name: /epss/i }))

    expect(submit().active_analyzers).toEqual(['trivy'])
  })
})
