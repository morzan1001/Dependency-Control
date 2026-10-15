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
})
