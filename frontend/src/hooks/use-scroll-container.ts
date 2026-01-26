import { useLayoutEffect, useState, useRef, RefObject } from 'react'
import { logger } from '@/lib/logger'

interface ScrollContainerResult {
  parentRef: RefObject<HTMLDivElement | null>
  scrollContainer: HTMLElement | null
  tableOffset: number
}

/**
 * Hook to find and track the main scroll container for virtualized tables.
 * Uses `closest('main')` from the component's position in the DOM,
 * which is more robust than global `document.querySelector('main')`.
 * 
 * Returns the scroll container element and calculates the table offset
 * for proper virtual scroll positioning.
 */
export function useScrollContainer(): ScrollContainerResult {
  const parentRef = useRef<HTMLDivElement>(null)
  const [scrollContainer, setScrollContainer] = useState<HTMLElement | null>(null)
  const [tableOffset, setTableOffset] = useState(0)

  useLayoutEffect(() => {
    if (!parentRef.current) return

    // Find the closest main element from this component's position
    // This is more robust than document.querySelector('main') since it
    // follows the actual component hierarchy
    const container = parentRef.current.closest('main') as HTMLElement | null
    
    if (!container) {
      // Fallback: try window scroll if no main container found
      logger.warn('useScrollContainer: No <main> container found, falling back to window scroll')
      return
    }

    setScrollContainer(container)

    const updateOffset = () => {
      if (parentRef.current && container) {
        const rect = parentRef.current.getBoundingClientRect()
        const containerRect = container.getBoundingClientRect()
        setTableOffset(rect.top - containerRect.top + container.scrollTop)
      }
    }

    updateOffset()
    
    // Update offset on resize
    window.addEventListener('resize', updateOffset)
    
    // Also update on scroll to handle dynamic content
    container.addEventListener('scroll', updateOffset, { passive: true })
    
    return () => {
      window.removeEventListener('resize', updateOffset)
      container.removeEventListener('scroll', updateOffset)
    }
  }, [])

  return { parentRef, scrollContainer, tableOffset }
}

/**
 * Creates a virtual scroll observer function for use with @tanstack/react-virtual.
 * Handles the scroll offset calculation relative to the table position.
 */
export function createScrollObserver(
  scrollContainer: HTMLElement | null,
  tableOffset: number
) {
  return (_instance: unknown, cb: (offset: number, isScrolling: boolean) => void) => {
    if (!scrollContainer) return undefined

    const onScroll = () => {
      const offset = scrollContainer.scrollTop - tableOffset
      cb(Math.max(0, offset), false)
    }

    scrollContainer.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    
    return () => {
      scrollContainer.removeEventListener('scroll', onScroll)
    }
  }
}
