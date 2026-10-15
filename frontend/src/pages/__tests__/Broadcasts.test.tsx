import { createContext, useContext } from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { toast } from 'sonner'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import Broadcasts from '../Broadcasts'

const mockSendBroadcast = vi.fn()
const mockUseTeams = vi.fn()

// Radix Tabs use pointer events jsdom can't drive; use a controlled stub.
const TabsCtx = createContext<{ value: string; onValueChange: (v: string) => void }>({
  value: '',
  onValueChange: () => {},
})
vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ value, onValueChange, children }: {
    value: string
    onValueChange: (v: string) => void
    children: React.ReactNode
  }) => (
    <TabsCtx.Provider value={{ value, onValueChange }}>{children}</TabsCtx.Provider>
  ),
  TabsList: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  TabsTrigger: ({ value, children }: { value: string; children: React.ReactNode }) => {
    const ctx = useContext(TabsCtx)
    return <button role="tab" onClick={() => ctx.onValueChange(value)}>{children}</button>
  },
  TabsContent: ({ value, children }: { value: string; children: React.ReactNode }) => {
    const ctx = useContext(TabsCtx)
    return ctx.value === value ? <div>{children}</div> : null
  },
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/hooks/queries/use-broadcast', () => ({
  useBroadcast: () => ({ mutateAsync: mockSendBroadcast, isPending: false }),
  useBroadcastHistory: () => ({ data: [], refetch: vi.fn(), isLoading: false }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({
  useTeams: () => mockUseTeams(),
}))
vi.mock('@/hooks/queries/use-system', () => ({
  useNotificationChannels: () => ['email'],
}))

// Radix Select isn't driveable in jsdom (pointer capture); use a native select.
vi.mock('@/components/ui/select', () => ({
  Select: ({ value, onValueChange, children }: {
    value: string
    onValueChange: (v: string) => void
    children: React.ReactNode
  }) => (
    <select
      data-testid="type-select"
      value={value}
      onChange={(e) => onValueChange(e.target.value)}
    >
      {children}
    </select>
  ),
  SelectItem: ({ value, children }: { value: string; children: React.ReactNode }) => (
    <option value={value}>{children}</option>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

// Replace the autocomplete with a plain input so we can set a package name.
vi.mock('@/components/ui/package-autocomplete', () => ({
  PackageAutocomplete: ({ value, onValueChange }: {
    value: string
    onValueChange: (v: string) => void
  }) => (
    <input
      data-testid="pkg-name"
      value={value}
      onChange={(e) => onValueChange(e.target.value)}
    />
  ),
}))

beforeEach(() => {
  mockSendBroadcast.mockReset()
  mockSendBroadcast.mockResolvedValue({ recipient_count: 0, project_count: 3 })
  mockUseTeams.mockReturnValue({ data: [] })
})

describe('Broadcasts - advisory package type reset', () => {
  it('can reset the package type back to "Any" (empty) after choosing a concrete type', async () => {
    render(<Broadcasts />)

    fireEvent.click(screen.getByRole('tab', { name: /Security Advisory/i }))

    fireEvent.change(screen.getByTestId('pkg-name'), { target: { value: 'log4j-core' } })

    const typeSelect = screen.getByTestId('type-select') as HTMLSelectElement

    fireEvent.change(typeSelect, { target: { value: 'maven' } })
    expect(typeSelect.value).toBe('maven')

    fireEvent.change(typeSelect, { target: { value: 'any' } })
    expect(typeSelect.value).toBe('any') // shown as "any", stored as ""

    fireEvent.click(screen.getByRole('button', { name: /Calculate Impact/i }))

    await waitFor(() => expect(mockSendBroadcast).toHaveBeenCalled())
    const payload = mockSendBroadcast.mock.calls[0][0]
    expect(payload.packages[0]).toMatchObject({ name: 'log4j-core', type: '' })
  })
})

describe('Broadcasts - advisory impact', () => {
  it('lists the matched versions that could not be compared with the max version', async () => {
    mockSendBroadcast.mockResolvedValue({
      recipient_count: 1,
      project_count: 0,
      uncomparable_versions: ['express (latest)'],
    })
    render(<Broadcasts />)

    fireEvent.click(screen.getByRole('tab', { name: /Security Advisory/i }))
    fireEvent.change(screen.getByTestId('pkg-name'), { target: { value: 'express' } })
    fireEvent.click(screen.getByRole('button', { name: /Calculate Impact/i }))

    expect(await screen.findByText(/express \(latest\)/)).toBeInTheDocument()
    expect(screen.getByText(/could not be compared/i)).toBeInTheDocument()
  })
})

describe('Broadcasts - channel selection', () => {
  it('sends an announcement only once a channel is chosen, on exactly that channel', async () => {
    render(<Broadcasts />)
    fireEvent.change(screen.getByLabelText('Subject'), { target: { value: 'Maintenance' } })
    fireEvent.change(screen.getByLabelText('Message'), { target: { value: 'Tonight' } })
    const send = screen.getByRole('button', { name: /Send Announcement/i })
    const email = screen.getByRole('checkbox', { name: /email/i })

    fireEvent.click(email)
    expect(send).toBeDisabled()

    fireEvent.click(email)
    fireEvent.click(send)

    await waitFor(() => expect(mockSendBroadcast).toHaveBeenCalled())
    expect(mockSendBroadcast.mock.calls[0][0].channels).toEqual(['email'])
  })

  it('keeps the advisory send disabled without a channel', () => {
    render(<Broadcasts />)
    fireEvent.click(screen.getByRole('tab', { name: /Security Advisory/i }))
    fireEvent.change(screen.getByLabelText('Advisory Subject'), { target: { value: 'log4j' } })
    fireEvent.change(screen.getByLabelText('Advisory Details'), { target: { value: 'Upgrade' } })
    fireEvent.change(screen.getByTestId('pkg-name'), { target: { value: 'log4j-core' } })

    fireEvent.click(screen.getByRole('checkbox', { name: /email/i }))

    expect(screen.getByRole('button', { name: /Broadcast Security Advisory/i })).toBeDisabled()
  })
})

describe('Broadcasts - team selection', () => {
  it('sends an announcement to exactly the teams left ticked', async () => {
    mockUseTeams.mockReturnValue({ data: [{ id: 't1', name: 'Payments' }, { id: 't2', name: 'Platform' }] })
    render(<Broadcasts />)
    fireEvent.click(screen.getByRole('button', { name: /Specific Teams/i }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Payments' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Platform' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Payments' }))
    fireEvent.change(screen.getByLabelText('Subject'), { target: { value: 'Maintenance' } })
    fireEvent.change(screen.getByLabelText('Message'), { target: { value: 'Tonight' } })

    fireEvent.click(screen.getByRole('button', { name: /Send Announcement/i }))

    await waitFor(() => expect(mockSendBroadcast).toHaveBeenCalled())
    expect(mockSendBroadcast.mock.calls[0][0]).toMatchObject({ target_type: 'teams', target_teams: ['t2'] })
  })
})

describe('Broadcasts - send failures', () => {
  beforeEach(() => {
    vi.mocked(toast.error).mockClear()
    mockSendBroadcast.mockRejectedValue(new Error('Network Error'))
  })

  it('names a failed announcement and why', async () => {
    render(<Broadcasts />)
    fireEvent.change(screen.getByLabelText('Subject'), { target: { value: 'Maintenance' } })
    fireEvent.change(screen.getByLabelText('Message'), { target: { value: 'Tonight' } })

    fireEvent.click(screen.getByRole('button', { name: /Send Announcement/i }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to send announcement', { description: 'Network Error' }))
  })

  it('names a failed advisory and why', async () => {
    render(<Broadcasts />)
    fireEvent.click(screen.getByRole('tab', { name: /Security Advisory/i }))
    fireEvent.change(screen.getByLabelText('Advisory Subject'), { target: { value: 'log4j' } })
    fireEvent.change(screen.getByLabelText('Advisory Details'), { target: { value: 'Upgrade' } })
    fireEvent.change(screen.getByTestId('pkg-name'), { target: { value: 'log4j-core' } })

    fireEvent.click(screen.getByRole('button', { name: /Broadcast Security Advisory/i }))

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Failed to send advisory', { description: 'Network Error' }))
  })
})

describe('Broadcasts - history on a phone', () => {
  it('says there is no history under the table, where a phone shows it, instead of in a row centred on the scrolling table', () => {
    render(<Broadcasts />)
    fireEvent.click(screen.getByRole('tab', { name: /History/i }))

    expect(screen.getByText('No broadcast history found.').closest('table')).toBeNull()
  })
})
