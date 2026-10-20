import { fireEvent, render, screen, within } from '@testing-library/react'
import { expectEveryFieldNamed } from '@/test/form-field'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { CreateGlobalWaiverDialog } from '../CreateGlobalWaiverDialog'

const mutate = vi.fn()
const mockUseCreateWaiver = vi.fn()

vi.mock('@/hooks/queries/use-waivers', () => ({
  useCreateWaiver: (meta: unknown) => {
    mockUseCreateWaiver(meta)
    return { mutate, isPending: false }
  },
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

  it.each([
    ['CVE-2021-23337', undefined, 'CVE-2021-23337'],
    ['GHSA-35jh-r3h4-6jhm', undefined, 'GHSA-35jh-r3h4-6jhm'],
    ['GO-2022-0969', undefined, 'GO-2022-0969'],
    ['lodash:4.17.20', 'lodash:4.17.20', undefined],
    ['go-md2man:2.0.2', 'go-md2man:2.0.2', undefined],
  ])('sends %s where the waiver can match it', (entered, findingId, vulnerabilityId) => {
    render(<CreateGlobalWaiverDialog open onOpenChange={() => {}} />)
    const dialog = screen.getByRole('dialog')

    fireEvent.click(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(screen.getByRole('option', { name: 'Vulnerability' }))
    fireEvent.change(within(dialog).getByPlaceholderText('e.g. CVE-2023-1234'), { target: { value: entered } })
    fireEvent.change(within(dialog).getByPlaceholderText('Why is this finding being waived globally?'), {
      target: { value: 'reviewed' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create Global Waiver' }))

    const [payload] = mutate.mock.calls[0]
    expect([payload.finding_type, payload.finding_id, payload.vulnerability_id]).toEqual([
      'vulnerability',
      findingId,
      vulnerabilityId,
    ])
  })

  it('asks for no rule on a finding scope waiver', () => {
    render(<CreateGlobalWaiverDialog open onOpenChange={() => {}} />)

    expect(screen.queryByPlaceholderText(RULE_PLACEHOLDER)).toBeNull()
  })
})

describe('CreateGlobalWaiverDialog failure', () => {
  it('names a failed creation, which the error toast completes with the reason', () => {
    render(<CreateGlobalWaiverDialog open onOpenChange={() => {}} />)

    expect(mockUseCreateWaiver).toHaveBeenCalledWith({ errorTitle: 'Failed to create global waiver' })
  })
})

describe('CreateGlobalWaiverDialog accessible names', () => {
  it('names every field by its label rather than its example placeholder', () => {
    render(<CreateGlobalWaiverDialog open onOpenChange={() => {}} />)

    expectEveryFieldNamed()
    for (const name of ['Finding ID', 'Package Name', 'Package Version', 'Reason']) {
      expect(screen.getByRole('textbox', { name })).toBeInTheDocument()
    }
    for (const name of ['Finding Type', 'Scope', 'Status']) {
      expect(screen.getByRole('combobox', { name })).toBeInTheDocument()
    }
    expect(screen.getByLabelText('Expiration Date (Optional)')).toHaveAttribute('type', 'date')
  })
})
