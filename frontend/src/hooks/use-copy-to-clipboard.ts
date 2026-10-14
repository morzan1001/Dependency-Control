import { useState, useCallback, type MouseEvent } from 'react'
import { toast } from 'sonner'
import { COPY_FEEDBACK_DELAY_MS } from '@/lib/constants'
import { logger } from '@/lib/logger'

interface UseCopyToClipboardReturn {
  copied: boolean
  copy: (text: string, e?: MouseEvent<HTMLElement>) => Promise<void>
}

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

// An insecure context or a denied permission rejects the write; the user must learn that while the text is on screen.
export async function copyWithToast(text: string, what: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(`${what.charAt(0).toUpperCase()}${what.slice(1)} copied to clipboard`)
    return true
  } catch {
    toast.error('Could not reach the clipboard', { description: `Select the ${what} and copy it by hand` })
    return false
  }
}
