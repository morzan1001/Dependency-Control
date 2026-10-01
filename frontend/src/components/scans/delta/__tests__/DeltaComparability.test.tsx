import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { DeltaComparability } from '../DeltaComparability'
import type { ScanDeltaResponse } from '@/types/scanDelta'

const FROM_SCAN_ID = 'a'
const TO_SCAN_ID = 'b'
const PROJECT_ID = 'p1'
const FIRST_PAGE = 1
const PAGE_SIZE = 50
const ONE_PAGE = 1
const COVERABLE = 120
const ANALYSED = 118
const NOT_ANALYSED = 0
const FROM_WAIVED = 12
const TO_WAIVED = 9
const SAME_WAIVED = 4
const NO_WAIVERS = 0
const WAIVER_ONLY = 2
const ONE_WAIVER_ONLY = 1
const NO_WAIVER_ONLY = 0
const RISK_SCORE_WARNING = /only its risk scores are reachability-adjusted/i
const LAPSED_WAIVER_WARNING = /before treating an added finding as newly introduced/i
const BOTH_SIDES_HIDE = /sit below what the two scans themselves report/i

// Annotated, not inferred: an inferred fixture drops a field from the response type silently.
function delta(overrides: Partial<ScanDeltaResponse> = {}): ScanDeltaResponse {
  return {
    category: 'findings',
    from_scan_id: FROM_SCAN_ID,
    to_scan_id: TO_SCAN_ID,
    project_id: PROJECT_ID,
    totals: { added: 0, removed: 0, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
    page: FIRST_PAGE,
    page_size: PAGE_SIZE,
    total_pages: ONE_PAGE,
    items: [],
    from_waived_excluded: NO_WAIVERS,
    to_waived_excluded: NO_WAIVERS,
    waiver_only_changes: NO_WAIVER_ONLY,
    ...overrides,
  }
}

describe('DeltaComparability', () => {
  afterEach(cleanup)

  it('stays out of the way when neither side has anything to explain', () => {
    const { container } = render(<DeltaComparability delta={delta()} />)

    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing before the first response lands', () => {
    const { container } = render(<DeltaComparability delta={null} />)

    expect(container).toBeEmptyDOMElement()
  })

  it('names the reachability each side was scored with and warns that scores cannot be compared', () => {
    render(
      <DeltaComparability
        delta={delta({
          from_reachability: { coverable_count: COVERABLE, analyzed_count: NOT_ANALYSED },
          to_reachability: { coverable_count: COVERABLE, analyzed_count: ANALYSED },
        })}
      />,
    )

    expect(screen.getByText(new RegExp(`reachability ${NOT_ANALYSED}/${COVERABLE} analysed`))).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`reachability ${ANALYSED}/${COVERABLE} analysed`))).toBeInTheDocument()
    expect(screen.getByText(RISK_SCORE_WARNING)).toBeInTheDocument()
  })

  it('says a side reports no reachability at all rather than printing a zero', () => {
    render(
      <DeltaComparability
        delta={delta({ to_reachability: { coverable_count: COVERABLE, analyzed_count: ANALYSED } })}
      />,
    )

    expect(screen.getByText(/no reachability/)).toBeInTheDocument()
    expect(screen.getByText(RISK_SCORE_WARNING)).toBeInTheDocument()
  })

  it('leaves the scores alone when both sides carry the same kind of enrichment', () => {
    render(
      <DeltaComparability
        delta={delta({
          from_reachability: { coverable_count: COVERABLE, analyzed_count: ANALYSED },
          to_reachability: { coverable_count: COVERABLE, analyzed_count: ANALYSED },
        })}
      />,
    )

    expect(screen.queryByText(RISK_SCORE_WARNING)).not.toBeInTheDocument()
  })

  it('counts the waived findings hidden per side and says how many changes a waiver explains', () => {
    render(
      <DeltaComparability
        delta={delta({
          from_waived_excluded: FROM_WAIVED,
          to_waived_excluded: TO_WAIVED,
          waiver_only_changes: WAIVER_ONLY,
        })}
      />,
    )

    expect(screen.getByText(new RegExp(`${FROM_WAIVED} waived hidden`))).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`${TO_WAIVED} waived hidden`))).toBeInTheDocument()
    expect(screen.getByText(LAPSED_WAIVER_WARNING)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`^${WAIVER_ONLY} of these changes`))).toBeInTheDocument()
  })

  it('warns about a lapsed waiver even when both sides hide the same number of findings', () => {
    render(
      <DeltaComparability
        delta={delta({
          from_waived_excluded: SAME_WAIVED,
          to_waived_excluded: SAME_WAIVED,
          waiver_only_changes: ONE_WAIVER_ONLY,
        })}
      />,
    )

    expect(screen.getByText(LAPSED_WAIVER_WARNING)).toBeInTheDocument()
  })

  it('explains the shortfall without the lapsed-waiver warning when no change is a waiver difference', () => {
    render(
      <DeltaComparability
        delta={delta({ from_waived_excluded: FROM_WAIVED, to_waived_excluded: TO_WAIVED })}
      />,
    )

    expect(screen.getByText(BOTH_SIDES_HIDE)).toBeInTheDocument()
    expect(screen.queryByText(LAPSED_WAIVER_WARNING)).not.toBeInTheDocument()
  })
})
