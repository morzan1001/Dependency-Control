/**
 * Copyable code/text components
 * Reusable component for displaying copyable code blocks
 */

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'

interface CopyableCodeProps {
  value: string
  className?: string
}

export function CopyableCode({ value, className = '' }: CopyableCodeProps) {
  const [copied, setCopied] = useState(false)
  
  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
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

/**
 * Inline copyable text (smaller, inline usage)
 */
export function CopyableText({ value, className = '' }: CopyableCodeProps) {
  const [copied, setCopied] = useState(false)
  
  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  
  return (
    <span 
      className={`inline-flex items-center gap-1 cursor-pointer hover:bg-muted/50 rounded px-1 ${className}`}
      onClick={handleCopy}
      title="Click to copy"
    >
      <code className="text-xs font-mono">{value}</code>
      {copied ? (
        <Check className="h-3 w-3 text-green-500" />
      ) : (
        <Copy className="h-3 w-3 opacity-50 hover:opacity-100" />
      )}
    </span>
  )
}
