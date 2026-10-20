import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ConversationHistoryDialog } from '../ConversationHistoryDialog'

describe('ConversationHistoryDialog accessible names', () => {
  it('names its search box by more than its placeholder', () => {
    render(
      <ConversationHistoryDialog
        open
        onOpenChange={vi.fn()}
        conversations={[]}
        activeId={null}
        onSelect={vi.fn()}
        onCreate={vi.fn()}
        onDelete={vi.fn()}
        canDelete={false}
      />,
    )

    expect(screen.getByRole('textbox', { name: 'Search conversations' })).toBeInTheDocument()
  })
})
