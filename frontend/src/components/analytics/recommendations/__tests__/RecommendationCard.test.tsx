import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect } from 'vitest'

import { RecommendationCard } from '../RecommendationCard'
import type { Recommendation, RecommendationAction } from '@/types/analytics'

function makeRecommendation(action: RecommendationAction): Recommendation {
  return {
    type: 'recurring_vulnerability',
    priority: 'high',
    title: 'Test recommendation',
    description: 'A test recommendation',
    impact: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
    affected_components: [],
    action,
    effort: 'medium',
  }
}

function renderExpanded(recommendation: Recommendation) {
  render(
    <MemoryRouter>
      <RecommendationCard recommendation={recommendation} />
    </MemoryRouter>,
  )
  fireEvent.click(screen.getByRole('button', { expanded: false }))
}

describe('RecommendationCard CVE rendering', () => {
  it('renders each recurring CVE only once', () => {
    renderExpanded(
      makeRecommendation({
        type: 'address_recurring',
        cves: ['CVE-2021-0001'],
      }),
    )
    expect(screen.getAllByText('CVE-2021-0001')).toHaveLength(1)
  })

  it('renders each cross-project CVE only once', () => {
    renderExpanded(
      makeRecommendation({
        type: 'fix_cross_project_vuln',
        cves: [{ cve: 'CVE-2021-0002', total_affected: 3, affected_projects: ['a', 'b', 'c'] }],
      }),
    )
    expect(screen.getAllByText('CVE-2021-0002')).toHaveLength(1)
  })

  it('still renders the generic Related Vulnerabilities block for other action types', () => {
    renderExpanded(
      makeRecommendation({
        type: 'update_dependency',
        cves: ['CVE-2021-0003'],
      }),
    )
    expect(screen.getByText('Related Vulnerabilities')).toBeInTheDocument()
    expect(screen.getAllByText('CVE-2021-0003')).toHaveLength(1)
  })
})
