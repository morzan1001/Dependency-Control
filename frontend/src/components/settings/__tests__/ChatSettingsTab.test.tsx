import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ChatSettingsTab } from '../ChatSettingsTab'

function renderTab(isPending = false) {
  const handleInputChange = vi.fn()
  render(
    <ChatSettingsTab
      formData={{ chat_rate_limit_per_minute: 10, chat_rate_limit_per_hour: 60, chat_max_tool_rounds: 20 }}
      handleInputChange={handleInputChange}
      handleSave={vi.fn()}
      hasPermission={() => true}
      isPending={isPending}
    />,
  )
  return handleInputChange
}

describe('ChatSettingsTab', () => {
  it.each([
    ['Messages per Minute', '5000', 'chat_rate_limit_per_minute', 1000],
    ['Messages per Minute', '0', 'chat_rate_limit_per_minute', 1],
    ['Messages per Hour', '-3', 'chat_rate_limit_per_hour', 1],
    ['Max Tool-Call Rounds', '99', 'chat_max_tool_rounds', 50],
    ['Max Tool-Call Rounds', '0', 'chat_max_tool_rounds', 1],
    ['Max Tool-Call Rounds', '7', 'chat_max_tool_rounds', 7],
  ])('holds %s typed as %s to its bounds', (label, typed, field, stored) => {
    const handleInputChange = renderTab()

    fireEvent.change(screen.getByLabelText(label), { target: { value: typed } })

    expect(handleInputChange).toHaveBeenCalledWith(field, stored)
  })

  it('titles its cards and save buttons in title case, like the other settings tabs', () => {
    renderTab()

    expect(screen.getAllByRole('heading').map((heading) => heading.textContent)).toEqual(['Rate Limits', 'Reasoning Budget'])
    expect(screen.getAllByRole('button').map((button) => button.textContent)).toEqual(['Save Rate Limits', 'Save Reasoning Budget'])
  })

  it('says "Saving..." on both buttons while saving, like the other settings tabs', () => {
    renderTab(true)

    expect(screen.getAllByRole('button').map((button) => button.textContent)).toEqual(['Saving...', 'Saving...'])
  })

  it('opens with the limits governing MCP tool calls as well as chat messages', () => {
    renderTab()

    expect(screen.getByText(/^Per-user sliding-window limits on chat messages and MCP tool calls\./)).toBeInTheDocument()
  })

  it('keeps the current value when the field is cleared', () => {
    const handleInputChange = renderTab()

    fireEvent.change(screen.getByLabelText('Messages per Hour'), { target: { value: '' } })

    expect(handleInputChange).toHaveBeenCalledWith('chat_rate_limit_per_hour', 60)
  })
})
