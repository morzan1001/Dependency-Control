import type { ReactNode } from 'react'
import { ExternalLink } from 'lucide-react'
import { cn } from '@/lib/utils'

export function ScmLink({ href, className, title, external = false, children }: Readonly<{
  href: string | null | undefined
  className?: string
  title?: string
  external?: boolean
  children: ReactNode
}>) {
  if (!href) return <span className={className} title={title}>{children}</span>
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={title}
      onClick={(e) => e.stopPropagation()}
      className={cn('text-primary hover:underline', className)}
    >
      {children}
      {external && <ExternalLink className="h-3 w-3" />}
    </a>
  )
}
