import { useLayoutEffect, useState, useRef, RefObject } from 'react'
import { logger } from '@/lib/logger'

interface ScrollContainerResult {
  parentRef: RefObject<HTMLDivElement | null>
  scrollContainer: HTMLElement | null
  tableOffsetRef: RefObject<number>
}

/**
 * Hook to find and track the main scroll container for virtualized tables.
 * Uses `closest('main')` from the component's position in the DOM,
 * which is more robust than global `document.querySelector('main')`.
 *
 * Returns the scroll container element and a ref-based table offset.
 * The offset is stored in a ref so the scroll observer always reads the
 * latest value without needing to re-subscribe (TanStack Virtual does NOT
 * re-subscribe when observeElementOffset changes).
 */
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

    window.addEventListener('resize', updateOffset)

    return () => {
      window.removeEventListener('resize', updateOffset)
    }
  }, [])

  return { parentRef, scrollContainer, tableOffsetRef }
}

/**
 * Creates a virtual scroll observer function for use with @tanstack/react-virtual.
 * Handles the scroll offset calculation relative to the table position
 * and properly tracks isScrolling state for the virtualizer.
 */
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
    reportOffset(false) // Initial position, not scrolling

    return () => {
      scrollContainer.removeEventListener('scroll', onScroll)
      if (scrollEndTimer) clearTimeout(scrollEndTimer)
    }
  }
}
