import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import { AnalyzerChecklist } from '../AnalyzerChecklist'

describe('AnalyzerChecklist', () => {
  it('offers the CBOMkit switch that the CBOM pipeline template reads', () => {
    const onToggle = vi.fn()
    render(<AnalyzerChecklist idPrefix="settings" selected={[]} onToggle={onToggle} />)

    fireEvent.click(screen.getByLabelText('CBOMkit (Crypto)'))

    expect(onToggle).toHaveBeenCalledWith('cbomkit')
  })
})
