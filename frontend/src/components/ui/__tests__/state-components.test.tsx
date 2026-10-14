import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { NoData } from '../state-components'

describe('state-components (surviving exports)', () => {
  it('NoData derives its copy from the entity name', () => {
    render(<NoData entityName="findings" />)
    expect(screen.getByText('No findings found')).toBeInTheDocument()
  })
})
