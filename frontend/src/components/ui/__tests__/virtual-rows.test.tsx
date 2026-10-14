import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { VirtualRows } from '../virtual-rows'

interface Row {
  key: string
  label: string
}

const ROW_HEIGHT = 50
// Rows 0 and 30 share a key, as two search hits on one package version in one project do.
const ROWS: Row[] = Array.from({ length: 100 }, (_, i) => ({
  key: i === 0 || i === 30 ? 'twin' : `row-${i}`,
  label: `row ${i}`,
}))

function renderRows(): HTMLElement {
  const main = document.createElement('main')
  Object.defineProperty(main, 'offsetHeight', { value: 800, configurable: true })
  Object.defineProperty(main, 'scrollTop', { value: 0, writable: true, configurable: true })
  document.body.appendChild(main)
  const list = { rows: ROWS, hasMore: false, nextPageFailed: false, loadMore: vi.fn(), observeEnd: vi.fn() }
  render(
    <table>
      <tbody>
        <VirtualRows
          list={list}
          scrollContainer={main}
          tableOffsetRef={{ current: 0 }}
          estimateSize={ROW_HEIGHT}
          rowKey={(row) => row.key}
          colSpan={1}
          renderRow={(row, style) => <div style={style}>{row.label}</div>}
        />
      </tbody>
    </table>,
    { container: main },
  )
  return main
}

function scrollTo(main: HTMLElement, top: number) {
  act(() => {
    main.scrollTop = top
    fireEvent.scroll(main)
  })
}

afterEach(() => vi.restoreAllMocks())

describe('VirtualRows', () => {
  it('renders two rows that share a key once each while the window moves past one of them', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const main = renderRows()
    expect(screen.getAllByText('row 0')).toHaveLength(1)
    expect(screen.getAllByText('row 30')).toHaveLength(1)

    scrollTo(main, 40 * ROW_HEIGHT)
    expect(screen.queryByText('row 0')).not.toBeInTheDocument()
    expect(screen.getAllByText('row 30')).toHaveLength(1)

    scrollTo(main, 0)
    expect(screen.getAllByText('row 0')).toHaveLength(1)
    expect(screen.getAllByText('row 30')).toHaveLength(1)
    const keyWarnings = consoleError.mock.calls.filter(([message]) => String(message).includes('same key'))
    expect(keyWarnings).toEqual([])
  })
})
