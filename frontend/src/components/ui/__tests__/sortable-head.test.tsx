import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { Table, TableHeader, TableRow } from '../table'
import { SortableHead } from '../sortable-head'
import type { SortOrder } from '@/hooks/use-pagination-state'

function renderHead(sortBy: string, sortOrder: SortOrder, firstOrder?: SortOrder) {
  const toggleSort = vi.fn()
  render(
    <Table>
      <TableHeader>
        <TableRow>
          <SortableHead column="name" sort={{ sortBy, sortOrder, toggleSort }} firstOrder={firstOrder}>
            Name
          </SortableHead>
        </TableRow>
      </TableHeader>
    </Table>,
  )
  return { head: screen.getByRole('columnheader', { name: 'Name' }), toggleSort }
}

describe('SortableHead', () => {
  it('marks the column the rows are sorted by and the direction', () => {
    expect(renderHead('name', 'asc').head).toHaveAttribute('aria-sort', 'ascending')
    expect(screen.getByRole('columnheader').querySelector('svg.lucide-arrow-up')).not.toBeNull()
  })

  it('shows a descending sort with the down arrow', () => {
    expect(renderHead('name', 'desc').head).toHaveAttribute('aria-sort', 'descending')
    expect(screen.getByRole('columnheader').querySelector('svg.lucide-arrow-down')).not.toBeNull()
  })

  it('shows no direction on a column the rows are not sorted by', () => {
    const { head } = renderHead('created_at', 'desc')

    expect(head).not.toHaveAttribute('aria-sort')
    expect(head.querySelector('svg')).toBeNull()
  })

  it('sorts by its column on click, in the order the column starts with', () => {
    const { head, toggleSort } = renderHead('created_at', 'desc', 'asc')

    fireEvent.click(head)

    expect(toggleSort).toHaveBeenCalledWith('name', 'asc')
  })
})
