import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../dialog'

describe('DialogHeader', () => {
  it('keeps the close button corner free, so a long title wraps before it, and stays centred on a phone', () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Manage Permissions for a.very.long.username@example.com</DialogTitle>
            <DialogDescription>Select the permissions you want to assign to this user.</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    )

    const header = screen.getByRole('heading').parentElement
    expect(header).toHaveClass('px-6', 'text-center', 'sm:pl-0', 'sm:text-left')
    expect(screen.getByRole('button', { name: 'Close' })).toHaveClass('absolute', 'right-4', 'top-4')
  })
})

describe('DialogContent', () => {
  it('holds its content to the dialog width, so a wide table scrolls inside it instead of pushing the title off a phone screen', () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Team Webhooks</DialogTitle>
          <DialogDescription>Webhooks that receive notifications for all projects in this team.</DialogDescription>
        </DialogContent>
      </Dialog>,
    )

    expect(screen.getByRole('dialog')).toHaveClass('grid', 'grid-cols-1')
  })
})
