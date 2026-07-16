import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SecretPriorityCard } from '../SecretPriorityCard'
import type { SecretPrioritizedCounts } from '@/types/scan'

const counts: SecretPrioritizedCounts = {
  total: 10,
  verified_count: 2,
  in_current_tree_count: 6,
  historical_only_count: 3,
  unknown_tree_count: 1,
  actionable_count: 1,
  deprioritized_count: 2,
}

describe('SecretPriorityCard', () => {
  it('renders total and actionable/deprioritized counts', () => {
    render(<SecretPriorityCard counts={counts} />)
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('renders nothing when there are no secrets', () => {
    const { container } = render(
      <SecretPriorityCard counts={{ ...counts, total: 0 }} />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
