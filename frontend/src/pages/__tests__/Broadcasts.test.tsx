import { createContext, useContext } from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

import Broadcasts from '../Broadcasts'

// --- Mocks -----------------------------------------------------------------

const mockSendBroadcast = vi.fn()

// Radix Tabs triggers activate on pointer events, which jsdom does not drive.
// Replace with a minimal controlled implementation so clicks switch tabs.
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

vi.mock('@/hooks/queries/use-broadcast', () => ({
  useBroadcast: () => ({ mutateAsync: mockSendBroadcast, isPending: false }),
  useBroadcastHistory: () => ({ data: [], refetch: vi.fn(), isLoading: false }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({
  useTeams: () => ({ data: [] }),
}))
vi.mock('@/hooks/queries/use-system', () => ({
  useNotificationChannels: () => ({ data: ['email'] }),
}))

// Radix Select is not reliably driveable in jsdom (pointer capture). Replace it
// with a native <select> so we can exercise the "any" -> "" reset mapping.
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
})

describe('Broadcasts - advisory package type reset', () => {
  it('can reset the package type back to "Any" (empty) after choosing a concrete type', async () => {
    render(<Broadcasts />)

    // Move to the advisory tab.
    fireEvent.click(screen.getByRole('tab', { name: /Security Advisory/i }))

    // Give the package a name so it counts as a valid package.
    fireEvent.change(screen.getByTestId('pkg-name'), { target: { value: 'log4j-core' } })

    const typeSelect = screen.getByTestId('type-select') as HTMLSelectElement

    // Pick a concrete type, then reset back to "Any".
    fireEvent.change(typeSelect, { target: { value: 'maven' } })
    expect(typeSelect.value).toBe('maven')

    // The regression: without an "Any" item mapped to "", there was no way back.
    fireEvent.change(typeSelect, { target: { value: 'any' } })
    expect(typeSelect.value).toBe('any') // shown as "any", stored as ""

    // Calculate impact -> payload must carry an empty (type-agnostic) type.
    fireEvent.click(screen.getByRole('button', { name: /Calculate Impact/i }))

    await waitFor(() => expect(mockSendBroadcast).toHaveBeenCalled())
    const payload = mockSendBroadcast.mock.calls[0][0]
    expect(payload.packages[0]).toMatchObject({ name: 'log4j-core', type: '' })
  })
})
