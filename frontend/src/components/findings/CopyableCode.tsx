import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'
import { useCopyToClipboard } from '@/hooks/use-copy-to-clipboard'

interface CopyableCodeProps {
  value: string
  className?: string
}

export function CopyableCode({ value, className = '' }: CopyableCodeProps) {
  const { copied, copy } = useCopyToClipboard()

  const handleCopy = (e: React.MouseEvent<HTMLButtonElement>) => {
    copy(value, e)
  }

  return (
    <div className={`flex items-start gap-2 ${className}`}>
      <code className="flex-1 px-2 py-1 bg-background rounded text-xs font-mono break-all">
        {value}
      </code>
      <Button
        variant="ghost"
        size="icon"
        className="h-6 w-6 flex-shrink-0"
        onClick={handleCopy}
      >
        {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
      </Button>
    </div>
  )
}
