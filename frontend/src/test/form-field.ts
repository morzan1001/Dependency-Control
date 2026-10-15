import { screen } from '@testing-library/react'
import { expect } from 'vitest'

// The form dialogs' field pattern: the shared Label inside a grid gap-2 wrapper with its control.
export function expectFieldLabel(text: string) {
  const label = screen.getByText(text, { selector: 'label' })
  expect(label).toHaveClass('font-medium')
  expect(label.parentElement).toHaveClass('grid', 'gap-2')
}
