import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ChatInput } from '../ChatInput'

describe('ChatInput accessible names', () => {
  it('names the message box by more than its placeholder', () => {
    render(<ChatInput onSend={vi.fn()} disabled={false} />)

    expect(screen.getByRole('textbox', { name: 'Message' })).toBeInTheDocument()
  })
})
