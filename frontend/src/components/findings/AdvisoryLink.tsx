import { ExternalLink } from 'lucide-react'
import { Badge, type BadgeProps } from '@/components/ui/badge'
import { advisoryUrl } from '@/lib/finding-utils'
import { cn } from '@/lib/utils'

interface AdvisoryLinkProps {
  readonly id: string
  readonly href?: string | null
  readonly variant?: BadgeProps['variant']
}

export function AdvisoryLink({ id, href, variant = 'outline' }: AdvisoryLinkProps) {
  const link = href || advisoryUrl(id)
  // The filled variants bring their own hover colour; only outline needs one.
  const badge = (
    <Badge variant={variant} className={cn(link && 'cursor-pointer', link && variant === 'outline' && 'hover:bg-muted')}>
      {id}
      {link && <ExternalLink className="h-3 w-3 ml-1" />}
    </Badge>
  )
  if (!link) return badge
  return (
    <a
      href={link}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center"
      // A dialog's portal still bubbles React clicks to the row or card that opened it.
      onClick={(e) => e.stopPropagation()}
    >
      {badge}
    </a>
  )
}
