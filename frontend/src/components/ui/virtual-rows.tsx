import { Fragment, useEffect, useMemo, type CSSProperties, type ReactNode, type RefObject } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Loader2 } from 'lucide-react'

import type { InfiniteRows } from '@/hooks/use-infinite-rows'
import { createScrollObserver } from '@/hooks/use-scroll-container'
import { VIRTUAL_SCROLL_OVERSCAN } from '@/lib/constants'

interface VirtualRowsProps<T> {
  list: InfiniteRows<T>
  scrollContainer: HTMLElement | null
  tableOffsetRef: RefObject<number>
  estimateSize: number
  rowKey: (row: T) => string
  colSpan: number
  renderRow: (row: T, style: CSSProperties) => ReactNode
}

export function VirtualRows<T>({ list, scrollContainer, tableOffsetRef, estimateSize, rowKey, colSpan, renderRow }: Readonly<VirtualRowsProps<T>>) {
  const { rows, hasMore, loadMore } = list
  const observeElementOffset = useMemo(
    () => createScrollObserver(scrollContainer, tableOffsetRef),
    [scrollContainer, tableOffsetRef],
  )

  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: hasMore ? rows.length + 1 : rows.length,
    getScrollElement: () => scrollContainer,
    estimateSize: () => estimateSize,
    overscan: VIRTUAL_SCROLL_OVERSCAN,
    observeElementOffset,
    getItemKey: (index) => (index < rows.length ? `${rowKey(rows[index])}-${index}` : `loader-${index}`),
  })

  const virtualItems = virtualizer.getVirtualItems()
  const lastIndex = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1].index : -1

  useEffect(() => {
    if (lastIndex !== -1 && lastIndex >= rows.length - 1) loadMore()
  }, [lastIndex, rows.length, loadMore])

  return (
    <tr>
      <td colSpan={colSpan} className="p-0">
        <div style={{ height: `${virtualizer.getTotalSize()}px`, position: 'relative' }}>
          {virtualItems.map((item) => {
            const style: CSSProperties = { position: 'absolute', top: `${item.start}px`, left: 0, right: 0, height: `${item.size}px` }
            if (item.index >= rows.length) {
              return (
                <div key={item.key} className="flex items-center justify-center py-4" style={style}>
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              )
            }
            return <Fragment key={item.key}>{renderRow(rows[item.index], style)}</Fragment>
          })}
        </div>
      </td>
    </tr>
  )
}
