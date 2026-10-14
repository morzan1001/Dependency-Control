import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SystemSettings } from '@/types/system'

import { GeneralSettingsTab } from '../GeneralSettingsTab'

vi.mock('@/hooks/queries/use-system', () => ({ useAppConfig: () => ({ data: { archive_enabled: true } }) }))

const handleInputChange = vi.fn()

function renderTab(formData: Partial<SystemSettings>) {
  render(
    <GeneralSettingsTab
      formData={formData}
      handleInputChange={handleInputChange}
      handleSave={vi.fn()}
      hasPermission={() => true}
      isPending={false}
    />,
  )
}

describe('GeneralSettingsTab', () => {
  beforeEach(() => handleInputChange.mockClear())

  it('offers the global retention actions, archiving included where S3 is set up', () => {
    renderTab({ retention_mode: 'global', global_retention_action: 'delete' })

    fireEvent.click(screen.getByLabelText('Retention Action'))
    fireEvent.click(screen.getByRole('option', { name: 'Archive to S3' }))

    expect(handleInputChange).toHaveBeenCalledWith('global_retention_action', 'archive')
  })

  it('switches global re-scanning and sets its interval with the fields of the project settings', () => {
    renderTab({ rescan_mode: 'global', global_rescan_enabled: true, global_rescan_interval: 24 })

    fireEvent.click(screen.getByLabelText('Enable Re-scanning'))
    fireEvent.change(screen.getByLabelText('Interval (Hours)'), { target: { value: '12' } })

    expect(handleInputChange.mock.calls).toEqual([
      ['global_rescan_enabled', false],
      ['global_rescan_interval', 12],
    ])
  })

  it('falls back to a 24-hour interval when the field is cleared, as a project does', () => {
    renderTab({ rescan_mode: 'global', global_rescan_enabled: true, global_rescan_interval: 12 })

    fireEvent.change(screen.getByLabelText('Interval (Hours)'), { target: { value: '' } })

    expect(handleInputChange).toHaveBeenCalledWith('global_rescan_interval', 24)
  })
})
