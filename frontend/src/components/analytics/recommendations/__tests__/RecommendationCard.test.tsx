import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect } from 'vitest'

import { RecommendationCard } from '../RecommendationCard'
import type { Recommendation, RecommendationAction } from '@/types/analytics'

const COMPONENTS_LISTED = 20
const COMPONENTS_COVERED = 900
const FILES_LISTED = 5
const RANK = 3
const RANKED_OUT_OF = 43

function makeRecommendation(action: RecommendationAction, over: Partial<Recommendation> = {}): Recommendation {
  return {
    type: 'recurring_vulnerability',
    priority: 'high',
    title: 'Test recommendation',
    description: 'A test recommendation',
    impact: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
    affected_components: [],
    affected_components_total: 0,
    rank: 0,
    ranked_out_of: 0,
    action,
    effort: 'medium',
    ...over,
  }
}

function components(count: number): string[] {
  return Array.from({ length: count }, (_, index) => `pkg${index}@1.0.0`)
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

  it('names the components the recommendation covers, not the ones it listed', () => {
    renderExpanded(
      makeRecommendation(
        { type: 'update_dependency' },
        {
          affected_components: components(COMPONENTS_LISTED),
          affected_components_total: COMPONENTS_COVERED,
        },
      ),
    )
    expect(
      screen.getByText(`Affected Components (${COMPONENTS_LISTED} of ${COMPONENTS_COVERED.toLocaleString()})`),
    ).toBeInTheDocument()
  })

  it('counts the unlisted files against the population, not against the sample it was given', () => {
    const filesTotal = 900
    renderExpanded(
      makeRecommendation({
        type: 'fix_code',
        files: components(COMPONENTS_LISTED),
        files_total: filesTotal,
      }),
    )
    expect(screen.getByText(`...and ${(filesTotal - FILES_LISTED).toLocaleString()} more`)).toBeInTheDocument()
  })

  it('says a card is one of a ranked list that was cut', () => {
    render(
      <MemoryRouter>
        <RecommendationCard
          recommendation={makeRecommendation({ type: 'update_dependency' }, { rank: RANK, ranked_out_of: RANKED_OUT_OF })}
        />
      </MemoryRouter>,
    )
    expect(screen.getByText(`Ranked ${RANK} of ${RANKED_OUT_OF}`)).toBeInTheDocument()
  })

  it('says nothing about rank when the generator emitted its whole list', () => {
    render(
      <MemoryRouter>
        <RecommendationCard recommendation={makeRecommendation({ type: 'update_dependency' })} />
      </MemoryRouter>,
    )
    expect(screen.queryByText(/^Ranked /)).not.toBeInTheDocument()
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
