import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'

interface CodeBlockProps {
  readonly code: string
  readonly maxHeight?: string
}

export function CodeBlock({ code, maxHeight = '600px' }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const onCopy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="relative rounded-md bg-muted p-4">
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-2 top-2 h-8 w-8 bg-background/50 hover:bg-background"
        onClick={onCopy}
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
      <pre 
        className="overflow-auto text-xs font-mono whitespace-pre-wrap break-all"
        style={{ maxHeight }}
      >
        {code}
      </pre>
    </div>
  )
}
