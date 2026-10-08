import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { InlineError, NoData } from '../state-components'

describe('state-components (surviving exports)', () => {
  it('InlineError renders its message', () => {
    render(<InlineError message="Boom" />)
    expect(screen.getByText('Boom')).toBeInTheDocument()
  })

  it('NoData derives its copy from the entity name', () => {
    render(<NoData entityName="findings" />)
    expect(screen.getByText('No findings found')).toBeInTheDocument()
  })
})
