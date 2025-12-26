/**
 * FindingTypeBadge component
 * Displays finding type with consistent color coding
 */

import { Badge } from '@/components/ui/badge'
import { getFindingTypeBadgeStyle } from '@/lib/finding-utils'

interface FindingTypeBadgeProps {
  type: string
  className?: string
}

export function FindingTypeBadge({ type, className = '' }: FindingTypeBadgeProps) {
  const style = getFindingTypeBadgeStyle(type)
  
  return (
    <Badge 
      variant="outline"
      className={`${style.borderColor} ${style.bgColor} ${style.textColor} ${className}`}
    >
      {type}
    </Badge>
  )
}

/**
 * Displays multiple finding types as a row of badges
 */
interface FindingTypeBadgesProps {
  primaryType: string
  additionalTypes?: Array<{ type: string; severity?: string }>
  className?: string
}

export function FindingTypeBadges({ primaryType, additionalTypes, className = '' }: FindingTypeBadgesProps) {
  return (
    <div className={`flex flex-wrap gap-1 ${className}`}>
      <Badge variant="outline">{primaryType}</Badge>
      {additionalTypes?.map((addType, idx) => (
        <FindingTypeBadge key={idx} type={addType.type} />
      ))}
    </div>
  )
}
