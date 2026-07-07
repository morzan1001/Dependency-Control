import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { InlineError, EmptyState, NoData } from '../state-components'

describe('state-components (surviving exports)', () => {
  it('InlineError renders its message', () => {
    render(<InlineError message="Boom" />)
    expect(screen.getByText('Boom')).toBeInTheDocument()
  })

  it('EmptyState renders title/description and fires the action', () => {
    const onClick = vi.fn()
    render(
      <EmptyState
        title="Nothing here"
        description="Come back later"
        action={{ label: 'Do it', onClick }}
      />,
    )
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
    expect(screen.getByText('Come back later')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Do it' }))
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('NoData derives its copy from the entity name', () => {
    render(<NoData entityName="findings" />)
    expect(screen.getByText('No findings found')).toBeInTheDocument()
  })
})
