import { useLayoutEffect, useState, useRef, useCallback, RefObject } from 'react'
import { logger } from '@/lib/logger'

interface ScrollContainerResult {
  parentRef: RefObject<HTMLDivElement | null>
  scrollContainer: HTMLElement | null
  tableOffsetRef: RefObject<number>
  scrollToTable: () => void
}

// Offset lives in a ref because TanStack Virtual does not re-subscribe when observeElementOffset changes.
export function useScrollContainer(): ScrollContainerResult {
  const parentRef = useRef<HTMLDivElement>(null)
  const [scrollContainer, setScrollContainer] = useState<HTMLElement | null>(null)
  const tableOffsetRef = useRef(0)

  useLayoutEffect(() => {
    if (!parentRef.current) return

    const container = parentRef.current.closest('main') as HTMLElement | null

    if (!container) {
      logger.warn('useScrollContainer: No <main> container found, falling back to window scroll')
      return
    }

    setScrollContainer(container)

    const updateOffset = () => {
      if (parentRef.current && container) {
        const rect = parentRef.current.getBoundingClientRect()
        const containerRect = container.getBoundingClientRect()
        tableOffsetRef.current = rect.top - containerRect.top + container.scrollTop
      }
    }

    updateOffset()

    // Recompute the offset when layout above the table changes height.
    const resizeObserver = new ResizeObserver(() => {
      requestAnimationFrame(updateOffset)
    })
    const contentWrapper = container.firstElementChild
    if (contentWrapper) {
      resizeObserver.observe(contentWrapper)
    }

    window.addEventListener('resize', updateOffset)

    return () => {
      window.removeEventListener('resize', updateOffset)
      resizeObserver.disconnect()
    }
  }, [])

  const scrollToTable = useCallback(() => {
    if (scrollContainer) {
      scrollContainer.scrollTo({ top: tableOffsetRef.current, behavior: 'instant' })
    }
  }, [scrollContainer])

  return { parentRef, scrollContainer, tableOffsetRef, scrollToTable }
}

export function createScrollObserver(
  scrollContainer: HTMLElement | null,
  tableOffsetRef: RefObject<number>
) {
  return (_instance: unknown, cb: (offset: number, isScrolling: boolean) => void) => {
    if (!scrollContainer) return undefined

    let scrollEndTimer: ReturnType<typeof setTimeout> | null = null

    const reportOffset = (isScrolling: boolean) => {
      const offset = scrollContainer.scrollTop - (tableOffsetRef.current ?? 0)
      cb(Math.max(0, offset), isScrolling)
    }

    const onScroll = () => {
      reportOffset(true)
      if (scrollEndTimer) clearTimeout(scrollEndTimer)
      scrollEndTimer = setTimeout(() => reportOffset(false), 150)
    }

    scrollContainer.addEventListener('scroll', onScroll, { passive: true })
    reportOffset(false)

    return () => {
      scrollContainer.removeEventListener('scroll', onScroll)
      if (scrollEndTimer) clearTimeout(scrollEndTimer)
    }
  }
}
