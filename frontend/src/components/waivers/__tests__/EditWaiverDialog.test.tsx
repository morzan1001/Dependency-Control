import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { Waiver } from '@/types/waiver'
import { EditWaiverDialog } from '../EditWaiverDialog'

const mutate = vi.fn()
vi.mock('@/hooks/queries/use-waivers', () => ({
  useUpdateWaiver: () => ({ mutate, isPending: false }),
}))

const EXPIRED: Waiver = {
  id: 'w1',
  package_name: 'lodash',
  reason: 'not reachable',
  status: 'accepted_risk',
  expiration_date: '2020-01-31T00:00:00Z',
  created_at: '2019-12-01T00:00:00Z',
  created_by: 'admin',
  is_active: true,
}

describe('EditWaiverDialog', () => {
  it('saves an expired waiver whose expiry date was left as it is', () => {
    render(<EditWaiverDialog waiver={EXPIRED} open onOpenChange={() => undefined} />)
    const date = document.querySelector<HTMLInputElement>('input[type="date"]')!

    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'still not reachable' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))

    expect(date.validity.rangeUnderflow).toBe(false)
    expect(mutate).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ reason: 'still not reachable' }) }),
      expect.anything(),
    )
  })
})
