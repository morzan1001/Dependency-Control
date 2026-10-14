import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import { CreateProjectDialog } from '../CreateProjectDialog'

const mockMutate = vi.fn()
const mockUseCreateProject = vi.fn()
let appConfig: { retention_mode: string; default_project_analyzers: string[]; global_retention_days?: number } | undefined

vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: appConfig }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-projects', () => ({
  useCreateProject: (meta: unknown) => {
    mockUseCreateProject(meta)
    return { mutate: mockMutate, isPending: false }
  },
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

  it('sends the retention the user set', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    fireEvent.change(screen.getByLabelText('Retention Period (Days)'), { target: { value: '30' } })
    fireEvent.click(screen.getByLabelText('Retention Action'))
    fireEvent.click(screen.getByRole('option', { name: 'None (Keep Forever)' }))

    expect(submit()).toMatchObject({ retention_days: 30, retention_action: 'none' })
  })

  it('leaves the retention to a global policy, which it names', () => {
    appConfig = { retention_mode: 'global', default_project_analyzers: [], global_retention_days: 0 }
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    expect(screen.getByText('Data retention is disabled (data is kept forever).')).toBeInTheDocument()
    const sent = submit()
    expect(sent.retention_days).toBeUndefined()
    expect(sent.retention_action).toBeUndefined()
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

  it('shows the key in the key rotation dialog\'s layout: default width, the one-time warning once, the key in a copy field', () => {
    mockMutate.mockImplementation((_vars, options: { onSuccess: (data: unknown) => void }) =>
      options.onSuccess({ project_id: 'p-new', api_key: API_KEY, note: 'This key will only be shown once. Please save it securely.' }),
    )
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    submit()

    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveClass('max-w-lg')
    expect(dialog).not.toHaveClass('sm:max-w-[600px]')
    expect(dialog).toHaveAccessibleDescription('Please save your API key securely. It will not be shown again.')
    expect(screen.queryByText('Success')).not.toBeInTheDocument()
    expect(screen.queryByText(/only be shown once/)).not.toBeInTheDocument()
    expect(screen.queryByText(/won't be able to see it again/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy API key' })).toBeInTheDocument()
    expect(screen.getByLabelText('Project ID')).toHaveValue('p-new')
    expect(screen.getByLabelText('Project ID')).toHaveAttribute('readonly')
  })

  it('focuses the API key with all of it selected, like the key rotation dialog', () => {
    mockMutate.mockImplementation((_vars, options: { onSuccess: (data: unknown) => void }) =>
      options.onSuccess({ project_id: 'p-new', api_key: API_KEY, note: 'Save the key' }),
    )
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    submit()

    const key = screen.getByDisplayValue(API_KEY) as HTMLInputElement
    expect(key).toHaveFocus()
    expect([key.selectionStart, key.selectionEnd]).toEqual([0, API_KEY.length])
  })

  describe('copying the API key', () => {
    const writeText = vi.fn()

    beforeEach(() => {
      vi.mocked(toast.success).mockClear()
      vi.mocked(toast.error).mockClear()
      // jsdom ships no Clipboard API.
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
      mockMutate.mockImplementation((_vars, options: { onSuccess: (data: unknown) => void }) =>
        options.onSuccess({ project_id: 'p-new', api_key: API_KEY, note: 'Save the key' }),
      )
    })

    function createAndCopyKey() {
      render(<CreateProjectDialog open onOpenChange={vi.fn()} />)
      submit()
      const copy = screen.getByRole('button', { name: 'Copy API key' })
      fireEvent.click(copy)
      return copy
    }

    it('confirms the copy and marks the button once the clipboard holds the key', async () => {
      writeText.mockResolvedValue(undefined)

      const copy = createAndCopyKey()

      await waitFor(() => expect(toast.success).toHaveBeenCalledWith('API key copied to clipboard'))
      expect(writeText.mock.calls).toEqual([[API_KEY]])
      expect(copy.querySelector('.lucide-check')).toBeInTheDocument()
    })

    it('tells the user to copy the key by hand and leaves the button unmarked when the clipboard refuses', async () => {
      writeText.mockRejectedValue(new Error('denied'))

      const copy = createAndCopyKey()

      await waitFor(() =>
        expect(toast.error).toHaveBeenCalledWith('Could not reach the clipboard', {
          description: expect.stringMatching(/copy it by hand/i),
        }),
      )
      expect(toast.success).not.toHaveBeenCalledWith(expect.stringMatching(/copied/i))
      expect(copy.querySelector('.lucide-check')).not.toBeInTheDocument()
      expect(screen.getByDisplayValue(API_KEY)).not.toHaveAttribute('type', 'password')
    })
  })
})

describe('CreateProjectDialog failure', () => {
  it('names a failed creation, which the error toast completes with the reason', () => {
    render(<CreateProjectDialog open onOpenChange={vi.fn()} />)

    expect(mockUseCreateProject).toHaveBeenCalledWith({ errorTitle: 'Failed to create project' })
  })
})
