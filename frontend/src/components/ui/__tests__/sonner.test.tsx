import { act, render, screen } from '@testing-library/react'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { Toaster } from '../sonner'

beforeEach(() => {
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
})

describe('Toaster', () => {
  it('keeps the line breaks of a description that lists several refusals', async () => {
    render(<Toaster />)

    act(() => {
      toast.error('Failed to save', { description: 'name: Field required\nemail: Email is invalid' })
    })

    expect(await screen.findByText(/name: Field required/)).toHaveClass('whitespace-pre-line')
  })
})
