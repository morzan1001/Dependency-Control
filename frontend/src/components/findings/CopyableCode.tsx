import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'
import { useCopyToClipboard } from '@/hooks/use-copy-to-clipboard'

export function CopyableCode({ value }: Readonly<{ value: string }>) {
  const { copied, copy } = useCopyToClipboard()

  return (
    <div className="flex items-start gap-2">
      <code className="flex-1 px-2 py-1 bg-background rounded text-xs font-mono break-all">
        {value}
      </code>
      <Button
        variant="ghost"
        size="icon"
        className="h-6 w-6 flex-shrink-0"
        onClick={(e) => copy(value, e)}
      >
        {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
      </Button>
    </div>
  )
}
