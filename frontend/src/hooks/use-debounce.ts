import { useEffect, useState } from 'react'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

/**
 * Hook that debounces a value, delaying updates until after the specified delay.
 * Useful for search inputs and other rapidly changing values.
 *
 * @param value - The value to debounce
 * @param delay - Delay in milliseconds (default: 300ms from constants)
 * @returns The debounced value
 *
 * @example
 * ```tsx
 * const [search, setSearch] = useState('')
 * const debouncedSearch = useDebounce(search, 300)
 *
 * useEffect(() => {
 *   // This runs 300ms after the user stops typing
 *   fetchResults(debouncedSearch)
 * }, [debouncedSearch])
 * ```
 */
export function useDebounce<T>(value: T, delay: number = DEBOUNCE_DELAY_MS): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value)

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay)

    return () => {
      clearTimeout(timer)
    }
  }, [value, delay])

  return debouncedValue
}
