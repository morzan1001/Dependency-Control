import { useState, useCallback, type MouseEvent } from 'react'
import { COPY_FEEDBACK_DELAY_MS } from '@/lib/constants'
import { logger } from '@/lib/logger'

interface UseCopyToClipboardReturn {
  copied: boolean
  copy: (text: string, e?: MouseEvent<HTMLElement>) => Promise<void>
}

/**
 * Hook for copying text to clipboard with automatic reset
 */
export function useCopyToClipboard(): UseCopyToClipboardReturn {
  const [copied, setCopied] = useState(false)

  const copy = useCallback(async (text: string, e?: MouseEvent<HTMLElement>) => {
    if (e) {
      e.stopPropagation()
    }

    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), COPY_FEEDBACK_DELAY_MS)
    } catch (error) {
      logger.error('Failed to copy to clipboard:', error)
    }
  }, [])

  return { copied, copy }
}
