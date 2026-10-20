import { screen } from '@testing-library/react'
import { expect } from 'vitest'

// The form dialogs' field pattern: the shared Label inside a grid gap-2 wrapper with its control.
export function expectFieldLabel(text: string) {
  const label = screen.getByText(text, { selector: 'label' })
  expect(label).toHaveClass('font-medium')
  expect(label.parentElement).toHaveClass('grid', 'gap-2')
}

const FIELD_ROLES = ['combobox', 'textbox', 'switch', 'checkbox', 'radiogroup', 'spinbutton'] as const

// Without a name a screen reader announces a bare "combobox" or "edit text"; a placeholder does not count.
export function expectEveryFieldNamed() {
  const fields = FIELD_ROLES.flatMap((role) => screen.queryAllByRole(role))
  expect(fields.length).toBeGreaterThan(0)
  for (const field of fields) expect(field, field.outerHTML.slice(0, 160)).toHaveAccessibleName()
}
