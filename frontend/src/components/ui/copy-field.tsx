import { useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { copyWithToast } from '@/hooks/use-copy-to-clipboard'
import { COPY_FEEDBACK_DELAY_MS } from '@/lib/constants'

export function CopyField({ value, what }: Readonly<{ value: string; what: string }>) {
  const [copied, setCopied] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  // A dialog selects its first field only as it opens, not when a submit swaps this field in.
  useEffect(() => {
    inputRef.current?.focus()
    inputRef.current?.select()
  }, [])

  const copy = async () => {
    if (await copyWithToast(value, what)) {
      setCopied(true)
      setTimeout(() => setCopied(false), COPY_FEEDBACK_DELAY_MS)
    }
  }

  return (
    <div className="flex items-center space-x-2">
      <Input ref={inputRef} value={value} readOnly aria-label={what} className="font-mono bg-muted" />
      <Button size="icon" variant="outline" aria-label={`Copy ${what}`} onClick={() => void copy()}>
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  )
}
