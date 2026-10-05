import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'
import { useCopyToClipboard } from '@/hooks/use-copy-to-clipboard'

interface CodeBlockProps {
  readonly code: string
  readonly maxHeight?: string
}

export function CodeBlock({ code, maxHeight = '600px' }: CodeBlockProps) {
  const { copied, copy } = useCopyToClipboard()

  return (
    <div className="relative rounded-md bg-muted p-4">
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-2 top-2 h-8 w-8 bg-background/50 hover:bg-background"
        aria-label="Copy"
        onClick={() => copy(code)}
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
