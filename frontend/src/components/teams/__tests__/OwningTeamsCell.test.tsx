import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'

import { OwningTeamsCell } from '../OwningTeamsCell'

const FOUR = [
  { id: 't1', name: 'Payments' },
  { id: 't2', name: 'Platform' },
  { id: 't3', name: 'Identity' },
  { id: 't4', name: 'Data' },
]

describe('OwningTeamsCell', () => {
  it('counts the owners the fixed-width cell cannot lay out', () => {
    render(<OwningTeamsCell teams={FOUR} />)

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.getByText('+3')).toBeInTheDocument()
  })

  it('carries every owner in the title, so the four are readable without leaving the table', () => {
    render(<OwningTeamsCell teams={FOUR} />)

    expect(screen.getByTitle('Payments, Platform, Identity, Data')).toBeInTheDocument()
  })

  it('says a project with no owner is unassigned rather than rendering a bare dash', () => {
    render(<OwningTeamsCell teams={[]} />)

    expect(screen.getByText('Unassigned')).toBeInTheDocument()
    expect(screen.queryByText('-')).not.toBeInTheDocument()
    expect(screen.queryByText('—')).not.toBeInTheDocument()
  })

  it('treats an absent field the same as no owner', () => {
    render(<OwningTeamsCell />)

    expect(screen.getByText('Unassigned')).toBeInTheDocument()
  })

  it('counts nothing when a single team owns the project', () => {
    render(<OwningTeamsCell teams={[FOUR[0]]} />)

    expect(screen.getByText('Payments')).toBeInTheDocument()
    expect(screen.queryByText('+0')).not.toBeInTheDocument()
  })
})
