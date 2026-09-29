import { fireEvent, render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { CreateGlobalWaiverDialog } from '../CreateGlobalWaiverDialog'

const mutate = vi.fn()

vi.mock('@/hooks/queries/use-waivers', () => ({
  useCreateWaiver: () => ({ mutate, isPending: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const RULE_PLACEHOLDER = 'e.g. javascript_lang_insufficiently_random_values'

describe('CreateGlobalWaiverDialog', () => {
  beforeEach(() => mutate.mockReset())

  it('sends the rule and the file a file scope waiver covers', () => {
    render(<CreateGlobalWaiverDialog open onOpenChange={() => {}} />)
    const dialog = screen.getByRole('dialog')

    fireEvent.click(within(dialog).getAllByRole('combobox')[1])
    fireEvent.click(screen.getByRole('option', { name: 'File (same rule in file)' }))
    fireEvent.change(within(dialog).getByPlaceholderText(RULE_PLACEHOLDER), { target: { value: 'weak_rng' } })
    fireEvent.change(within(dialog).getByPlaceholderText('e.g. lodash'), { target: { value: 'src/a.js' } })
    fireEvent.change(within(dialog).getByPlaceholderText('Why is this finding being waived globally?'), {
      target: { value: 'reviewed' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Global Waiver' }))

    expect(mutate).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'file', rule_id: 'weak_rng', package_name: 'src/a.js' }),
      expect.anything(),
    )
  })

  it('asks for no rule on a finding scope waiver', () => {
    render(<CreateGlobalWaiverDialog open onOpenChange={() => {}} />)

    expect(screen.queryByPlaceholderText(RULE_PLACEHOLDER)).toBeNull()
  })
})
