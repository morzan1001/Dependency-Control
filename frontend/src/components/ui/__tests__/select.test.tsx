import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../select'

describe('SelectTrigger', () => {
  it('aligns a label it clamps to one line left, like a label that fits, instead of centring it beside a gap', () => {
    render(
      <Select value="gitlab">
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="gitlab">Internal GitLab (https://gitlab.example.com)</SelectItem>
        </SelectContent>
      </Select>,
    )

    expect(screen.getByRole('combobox')).toHaveClass('text-left')
  })

  it('keeps the chevron at full size beside a value wider than the trigger', () => {
    renderLongValue()

    expect(screen.getByRole('combobox').querySelector('svg')).toHaveClass('shrink-0')
  })

  // Cut where the space ends instead of after the first word that fits, which left a gap before the chevron.
  it('cuts a value wider than the trigger with an ellipsis on one line', () => {
    renderLongValue()

    expect(screen.getByRole('combobox')).toHaveClass('[&>span]:truncate', '[&>span]:min-w-0')
  })
})

function renderLongValue() {
  render(
    <Select value="long">
      <SelectTrigger className="w-[180px]">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="long">eu-central-1-customer-acceptance release</SelectItem>
      </SelectContent>
    </Select>,
  )
}
