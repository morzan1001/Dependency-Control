import { Badge } from '@/components/ui/badge'

const STYLES: Record<string, { label: string; className: string }> = {
  added: { label: '+ added', className: 'border-green-500/20 bg-green-500/10 text-green-600' },
  removed: { label: '− removed', className: 'border-red-500/20 bg-red-500/10 text-red-600' },
  version_changed: { label: '↻ version', className: 'border-blue-500/20 bg-blue-500/10 text-blue-600' },
  license_changed: { label: '↻ license', className: 'border-yellow-500/20 bg-yellow-500/10 text-yellow-600' },
}

export function ChangeBadge({ change }: { readonly change: string }) {
  const style = STYLES[change] ?? { label: change, className: '' }
  return <Badge variant="secondary" className={style.className}>{style.label}</Badge>
}
