import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Button } from '../button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '../dialog'

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

describe('DialogFooter', () => {
  it('keeps a gap between its buttons both stacked on a phone and side by side', () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Invite User</DialogTitle>
          <DialogDescription>Send an invitation email to a new user.</DialogDescription>
          <DialogFooter>
            <Button variant="outline">Cancel</Button>
            <Button>Send Invitation</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>,
    )

    const footer = screen.getByRole('button', { name: 'Cancel' }).parentElement
    expect(footer).toHaveClass('flex-col-reverse', 'gap-2', 'sm:flex-row')
    expect(footer).not.toHaveClass('sm:space-x-2')
  })
})
