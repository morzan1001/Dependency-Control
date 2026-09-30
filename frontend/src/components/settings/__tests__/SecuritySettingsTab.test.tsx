import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
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

  it('keeps creating accounts on first SSO login until an admin switches it off', () => {
    const handleInputChange = vi.fn()
    render(
      <SecuritySettingsTab
        formData={{ oidc_enabled: true }}
        handleInputChange={handleInputChange}
        handleSave={() => {}}
        hasPermission={() => true}
        isPending={false}
      />,
    )
    const toggle = screen.getByRole('switch', { name: 'Create Accounts on First SSO Login' })

    expect(toggle).toBeChecked()
    fireEvent.click(toggle)
    expect(handleInputChange).toHaveBeenCalledWith('oidc_auto_provision', false)
  })
})
