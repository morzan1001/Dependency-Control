import { useState } from 'react'
import { Button } from '@/components/ui/button'

interface CollapsibleReferencesProps {
  references?: string[]
  title?: string
}

export function CollapsibleReferences({ references, title = 'References' }: CollapsibleReferencesProps) {
  const [isOpen, setIsOpen] = useState(false)

  if (!references || references.length === 0) return null

  return (
    <div className="pt-2">
      <Button 
        variant="ghost" 
        size="sm" 
        className="h-auto py-1 px-0 text-xs font-medium hover:bg-transparent hover:underline justify-start text-muted-foreground"
        onClick={() => setIsOpen(!isOpen)}
      >
        {isOpen ? '▼' : '▶'} {title} ({references.length})
      </Button>
      
      {isOpen && (
        <div className="flex flex-col gap-1 mt-1 pl-2 border-l-2 border-muted ml-1">
          {references.map((ref) => (
            <a
              key={ref}
              href={ref}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-blue-500 hover:underline truncate block"
            >
              {ref}
            </a>
          ))}
        </div>
      )}
    </div>
  )
}
