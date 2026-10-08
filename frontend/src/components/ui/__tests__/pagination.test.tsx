import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { Pagination } from '../pagination'

describe('Pagination', () => {
  it('renders nothing for a single page', () => {
    const { container } = render(<Pagination page={1} totalPages={1} onChange={vi.fn()} />)

    expect(container).toBeEmptyDOMElement()
  })

  it('names the page, the page count and, when given, the item total', () => {
    render(<Pagination page={2} totalPages={3} total={47} onChange={vi.fn()} />)

    expect(screen.getByText('Page 2 of 3 (47 total)')).toBeInTheDocument()
  })

  it('moves one page back or forward', () => {
    const onChange = vi.fn()
    render(<Pagination page={2} totalPages={3} onChange={onChange} />)

    fireEvent.click(screen.getByRole('button', { name: /previous/i }))
    fireEvent.click(screen.getByRole('button', { name: /next/i }))

    expect(onChange.mock.calls).toEqual([[1], [3]])
  })

  it('holds Previous on the first page and Next on the last', () => {
    const { rerender } = render(<Pagination page={1} totalPages={2} onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /next/i })).toBeEnabled()

    rerender(<Pagination page={2} totalPages={2} onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: /previous/i })).toBeEnabled()
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
  })

  it('holds Next while the caller says so', () => {
    render(<Pagination page={1} totalPages={3} nextDisabled onChange={vi.fn()} />)

    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled()
  })
})
