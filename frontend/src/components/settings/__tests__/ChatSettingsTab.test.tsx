import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ChatSettingsTab } from '../ChatSettingsTab'

function renderTab() {
  const handleInputChange = vi.fn()
  render(
    <ChatSettingsTab
      formData={{ chat_rate_limit_per_minute: 10, chat_rate_limit_per_hour: 60, chat_max_tool_rounds: 20 }}
      handleInputChange={handleInputChange}
      handleSave={vi.fn()}
      hasPermission={() => true}
      isPending={false}
    />,
  )
  return handleInputChange
}

describe('ChatSettingsTab', () => {
  it.each([
    ['Messages per minute', '5000', 'chat_rate_limit_per_minute', 1000],
    ['Messages per minute', '0', 'chat_rate_limit_per_minute', 1],
    ['Messages per hour', '-3', 'chat_rate_limit_per_hour', 1],
    ['Max tool-call rounds', '99', 'chat_max_tool_rounds', 50],
    ['Max tool-call rounds', '0', 'chat_max_tool_rounds', 1],
    ['Max tool-call rounds', '7', 'chat_max_tool_rounds', 7],
  ])('holds %s typed as %s to its bounds', (label, typed, field, stored) => {
    const handleInputChange = renderTab()

    fireEvent.change(screen.getByLabelText(label), { target: { value: typed } })

    expect(handleInputChange).toHaveBeenCalledWith(field, stored)
  })

  it('keeps the current value when the field is cleared', () => {
    const handleInputChange = renderTab()

    fireEvent.change(screen.getByLabelText('Messages per hour'), { target: { value: '' } })

    expect(handleInputChange).toHaveBeenCalledWith('chat_rate_limit_per_hour', 60)
  })
})
