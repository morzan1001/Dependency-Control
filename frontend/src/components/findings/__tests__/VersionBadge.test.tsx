import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'

import { VersionBadge } from '../VersionBadge'

const DIGEST = 'sha256:4f9a1c0e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f'

describe('VersionBadge', () => {
  // A container digest as version widened its column and squeezed the component next to it.
  it('caps a long version and cuts it with an ellipsis, the full version as tooltip', () => {
    render(<VersionBadge version={DIGEST} />)

    const text = screen.getByText(DIGEST)
    expect(text).toHaveClass('truncate')
    expect(text.parentElement).toHaveClass('min-w-0', 'max-w-[160px]')
    expect(text.parentElement).toHaveAttribute('title', DIGEST)
  })

  it('shows a short version as before', () => {
    render(<VersionBadge version="4.17.21" />)

    expect(screen.getByText('4.17.21')).toBeInTheDocument()
  })
})
