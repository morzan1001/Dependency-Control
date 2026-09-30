import { fireEvent, render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'

import { AnalyzerSettingsDialog } from '../AnalyzerSettingsDialog'
import { ANALYZER_SETTINGS_SCHEMAS } from '@/lib/analyzer-settings-schemas'

function renderDialog(currentValues: Record<string, unknown>) {
  const onSave = vi.fn()
  render(
    <AnalyzerSettingsDialog
      open
      onOpenChange={vi.fn()}
      schema={ANALYZER_SETTINGS_SCHEMAS.typosquatting}
      currentValues={currentValues}
      onSave={onSave}
      canEdit
    />
  )
  return onSave
}

function save(onSave: ReturnType<typeof vi.fn>) {
  fireEvent.click(screen.getByRole('button', { name: /save settings/i }))
  expect(onSave).toHaveBeenCalledTimes(1)
  return onSave.mock.calls[0][0]
}

describe('AnalyzerSettingsDialog', () => {
  it('shows the default of a key the project never set', () => {
    renderDialog({})

    expect(screen.getByLabelText('Minimum Similarity (0–1)')).toHaveValue(0.82)
  })

  it('saves only the key the user edited, so the backend default keeps applying to the rest', () => {
    const onSave = renderDialog({})

    fireEvent.change(screen.getByLabelText('HIGH Severity Above'), { target: { value: '0.93' } })

    expect(save(onSave)).toEqual({ high_similarity: 0.93 })
  })

  it('keeps a stored override the user left untouched', () => {
    const onSave = renderDialog({ similarity_threshold: 0.85 })

    fireEvent.change(screen.getByLabelText('HIGH Severity Above'), { target: { value: '0.93' } })

    expect(save(onSave)).toEqual({ similarity_threshold: 0.85, high_similarity: 0.93 })
  })
})
