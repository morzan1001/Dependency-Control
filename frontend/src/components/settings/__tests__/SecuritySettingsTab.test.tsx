import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { SecuritySettingsTab } from '../SecuritySettingsTab'

describe('SecuritySettingsTab', () => {
  afterEach(() => cleanup())

  it('shows an empty OIDC provider name as empty, since the backend rejects it on save', () => {
    render(
      <SecuritySettingsTab
        formData={{ oidc_enabled: true, oidc_provider_name: '' }}
        handleInputChange={() => {}}
        handleSave={() => {}}
        hasPermission={() => true}
        isPending={false}
      />,
    )
    expect(screen.getByLabelText('Provider Name')).toHaveValue('')
  })
})
