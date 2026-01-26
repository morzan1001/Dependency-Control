import { useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { CopyableCode } from '../CopyableCode'
import type { Finding } from '@/types/scan'
import { getSourceInfo } from '@/lib/finding-utils'
import { ChevronDown, ChevronRight, Package } from 'lucide-react'

export function OriginBadge({ finding }: { finding: Finding }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const sourceInfo = getSourceInfo(finding.source_type)

  if (!sourceInfo && !finding.purl && finding.direct === undefined) {
    return null
  }

  const IconComponent = sourceInfo?.icon || Package
  const label = sourceInfo?.label || 'Package'
  const color = sourceInfo?.color || 'text-muted-foreground'

  return (
    <>
      <Badge
        variant="outline"
        className="cursor-pointer hover:bg-muted/50 transition-colors"
        onClick={(e) => {
          e.preventDefault()
          e.stopPropagation()
          setIsExpanded(!isExpanded)
        }}
      >
        <IconComponent className={`h-3 w-3 mr-1 ${color}`} />
        <span>{label}</span>
        {isExpanded ? <ChevronDown className="h-3 w-3 ml-1" /> : <ChevronRight className="h-3 w-3 ml-1" />}
      </Badge>

      {isExpanded && (
        <div className="w-full mt-2 p-3 border rounded-lg bg-muted/30 space-y-3 text-sm">
          {finding.direct !== undefined && (
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Dependency Type:</span>
              <Badge variant={finding.direct ? 'default' : 'secondary'}>
                {finding.direct ? 'Direct' : 'Transitive'}
              </Badge>
            </div>
          )}

          {finding.source_target && (
            <div>
              <span className="text-muted-foreground block mb-1">Source:</span>
              <CopyableCode value={finding.source_target} />
            </div>
          )}

          {finding.layer_digest && (
            <div>
              <span className="text-muted-foreground block mb-1">Container Layer:</span>
              <CopyableCode value={finding.layer_digest} />
            </div>
          )}

          {finding.purl && (
            <div>
              <span className="text-muted-foreground block mb-1">Package URL (PURL):</span>
              <CopyableCode value={finding.purl} />
            </div>
          )}

          {finding.locations && finding.locations.length > 0 && (
            <div>
              <span className="text-muted-foreground block mb-1">File Locations ({finding.locations.length}):</span>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {finding.locations.map((loc, i) => (
                  <code key={i} className="block px-2 py-0.5 bg-background rounded text-xs font-mono break-all">
                    {loc}
                  </code>
                ))}
              </div>
            </div>
          )}

          {finding.found_by && (
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Found By:</span>
              <Badge variant="outline" className="text-xs">
                {finding.found_by}
              </Badge>
            </div>
          )}
        </div>
      )}
    </>
  )
}
