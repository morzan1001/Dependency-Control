import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { TooltipProvider } from '@/components/ui/tooltip'
import { EpssCell, KevCell, ExploitMaturityBadge } from '../enrichment-cells'

// The tooltip primitives require a provider ancestor; the real tables hoist a
// single one around the card, so mirror that here.
function renderCell(node: React.ReactElement) {
  return render(<TooltipProvider>{node}</TooltipProvider>)
}

describe('EpssCell', () => {
  it('renders a dash when the score is missing', () => {
    renderCell(<EpssCell score={undefined} variant="impact" />)
    expect(screen.getByText('-')).toBeInTheDocument()
  })

  it('renders the formatted score without a Top-percentile sub-line for the impact variant', () => {
    renderCell(<EpssCell score={0.5} percentile={90} variant="impact" />)
    expect(screen.getByText('50.0%')).toBeInTheDocument()
    expect(screen.queryByText(/^Top /)).not.toBeInTheDocument()
  })

  it('renders the Top-percentile sub-line for the hotspot variant', () => {
    renderCell(<EpssCell score={0.5} percentile={90} variant="hotspot" />)
    expect(screen.getByText('50.0%')).toBeInTheDocument()
    expect(screen.getByText('Top 10%')).toBeInTheDocument()
  })
})

describe('KevCell', () => {
  it('renders a dash when there is no KEV', () => {
    renderCell(<KevCell hasKev={false} />)
    expect(screen.getByText('-')).toBeInTheDocument()
  })

  it('shows the KEV badge with a count', () => {
    renderCell(<KevCell hasKev kevCount={3} />)
    expect(screen.getByText('KEV (3)')).toBeInTheDocument()
  })

  it('shows the Ransomware label only when ransomwareLabel is set (impact variant)', () => {
    renderCell(<KevCell hasKev ransomwareUse ransomwareLabel />)
    expect(screen.getByText('Ransomware')).toBeInTheDocument()
  })

  it('omits the Ransomware text for the icon-only hotspot variant', () => {
    renderCell(<KevCell hasKev ransomwareUse />)
    expect(screen.queryByText('Ransomware')).not.toBeInTheDocument()
  })
})

describe('ExploitMaturityBadge', () => {
  it('renders nothing for unknown or absent maturity', () => {
    const { container } = renderCell(<ExploitMaturityBadge maturity="unknown" />)
    expect(container).toHaveTextContent('')
    expect(screen.queryByText('unknown')).not.toBeInTheDocument()
  })

  it('renders the maturity label for a known maturity', () => {
    renderCell(<ExploitMaturityBadge maturity="active" />)
    expect(screen.getByText('active')).toBeInTheDocument()
  })
})
