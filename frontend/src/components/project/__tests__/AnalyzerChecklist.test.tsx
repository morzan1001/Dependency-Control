import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import { AnalyzerChecklist } from '../AnalyzerChecklist'

describe('AnalyzerChecklist', () => {
  it('offers the CBOMkit switch that the CBOM pipeline template reads', () => {
    const onToggle = vi.fn()
    render(<AnalyzerChecklist idPrefix="settings" labelledBy="analyzers-label" selected={[]} onToggle={onToggle} />)

    fireEvent.click(screen.getByLabelText('CBOMkit (Crypto)'))

    expect(onToggle).toHaveBeenCalledWith('cbomkit')
  })

  it("wraps an analyzer's badges and action under its name on a phone instead of scrolling the list sideways", () => {
    render(<AnalyzerChecklist idPrefix="settings" labelledBy="analyzers-label" selected={[]} onToggle={vi.fn()} />)

    expect(screen.getByText('Callgraph Required').parentElement).toHaveClass('flex-wrap')
  })
})
