import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'

import { Notice } from '../ThreatIntelNote'

const TEXT = 'Counted 41 of 48 projects'

describe('Notice', () => {
  it('warns in amber by default', () => {
    render(<Notice>{TEXT}</Notice>)

    expect(screen.getByText(TEXT)).toHaveClass('border-amber-400', 'bg-amber-50')
  })

  // Same box as the warning, only the colour says it informs rather than warns.
  it('informs in blue with the same shape', () => {
    render(<Notice tone="info">{TEXT}</Notice>)

    const box = screen.getByText(TEXT)
    expect(box).toHaveClass('rounded', 'border', 'p-2', 'text-xs', 'border-blue-400', 'bg-blue-50')
    expect(box).not.toHaveClass('bg-amber-50')
  })
})
