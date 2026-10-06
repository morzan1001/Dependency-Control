import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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

  it('warns when an enrichment is picked without a vulnerability scanner to feed it', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    fireEvent.click(screen.getByRole('checkbox', { name: /trivy/i }))

    expect(screen.getByText('Requires at least one vulnerability scanner to be enabled')).toBeInTheDocument()
  })

  it('sends the analyzers the user picked', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    fireEvent.click(screen.getByRole('checkbox', { name: /epss/i }))

    expect(submit().active_analyzers).toEqual(['trivy'])
  })
})

describe('CreateProjectDialog after a project was created', () => {
  const API_KEY = 'dck_secret_key'

  it.each([
    ['Escape', () => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' })],
    ['the corner X', () => fireEvent.click(screen.getByText('Close', { selector: 'span.sr-only' }).closest('button')!)],
  ])('opens on an empty form again after %s closed the API key screen', async (_how, close) => {
    mockMutate.mockImplementation((_vars, options: { onSuccess: (data: unknown) => void }) =>
      options.onSuccess({ project_id: 'p-new', api_key: API_KEY, note: 'Save the key' }),
    )
    const onOpenChange = vi.fn()
    const { rerender } = render(<CreateProjectDialog open onOpenChange={onOpenChange} />)
    submit()
    expect(screen.getByText('Project Created')).toBeInTheDocument()

    close()
    expect(onOpenChange).toHaveBeenCalledWith(false)
    rerender(<CreateProjectDialog open={false} onOpenChange={onOpenChange} />)
    rerender(<CreateProjectDialog open onOpenChange={onOpenChange} />)

    await waitFor(() => expect(screen.getByText('Create New Project')).toBeInTheDocument())
    expect(screen.queryByDisplayValue(API_KEY)).not.toBeInTheDocument()
    expect(screen.getByLabelText('Project Name')).toHaveValue('')
  })
})
