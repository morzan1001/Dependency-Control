import { fireEvent, render, screen } from '@testing-library/react'
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

describe('SelectContent with an entry wider than the screen', () => {
  const LONG_TEAM = 'Team-'.repeat(60)

  function openLongList() {
    render(
      <Select>
        <SelectTrigger aria-label="Team">
          <SelectValue placeholder="All Teams" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="long">{LONG_TEAM}</SelectItem>
        </SelectContent>
      </Select>,
    )
    fireEvent.click(screen.getByLabelText('Team'))
    return screen.getByRole('option')
  }

  it('caps the list at the space left on screen', () => {
    openLongList()

    expect(screen.getByRole('listbox')).toHaveClass('max-w-[min(var(--radix-select-content-available-width),24rem)]')
  })

  it('cuts a long entry with an ellipsis and keeps the full text as its tooltip', () => {
    const option = openLongList()

    expect(option).toHaveClass('[&>span:last-child]:min-w-0', '[&>span:last-child]:truncate')
    expect(option).toHaveAttribute('title', LONG_TEAM)
  })
})
