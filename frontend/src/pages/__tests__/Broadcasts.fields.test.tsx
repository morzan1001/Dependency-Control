import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import Broadcasts from '../Broadcasts'
import { expectEveryFieldNamed } from '@/test/form-field'

vi.mock('@/hooks/queries/use-broadcast', () => ({
  useBroadcast: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useBroadcastHistory: () => ({ data: [], refetch: vi.fn(), isLoading: false }),
  usePackageSuggestions: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-system', () => ({ useNotificationChannels: () => ['email'] }))

describe('Broadcasts accessible names', () => {
  it("links each affected package's labels to its fields, row by row", () => {
    render(<Broadcasts />)
    // Radix activates a tab on mouseDown.
    fireEvent.mouseDown(screen.getByRole('tab', { name: /Security Advisory/i }))
    fireEvent.click(screen.getByRole('button', { name: /Add Package/i }))

    expectEveryFieldNamed()
    expect(screen.getAllByRole('textbox', { name: 'Package Name' })).toHaveLength(2)
    expect(screen.getAllByRole('textbox', { name: 'Max Version (<=)' })).toHaveLength(2)
    expect(screen.getAllByRole('combobox', { name: 'Type (Optional)' })).toHaveLength(2)
  })
})

describe('Broadcasts team picker', () => {
  it('names the team checkboxes as a group by their label', () => {
    render(<Broadcasts />)
    fireEvent.click(screen.getByRole('button', { name: /Specific Teams/i }))

    expect(screen.getByRole('group', { name: 'Select Teams' })).toBeInTheDocument()
  })
})
