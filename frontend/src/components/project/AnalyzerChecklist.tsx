import type { ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { AVAILABLE_ANALYZERS, ANALYZER_CATEGORIES } from '@/lib/constants'
import { cn } from '@/lib/utils'

interface AnalyzerChecklistProps {
  idPrefix: string
  selected: readonly string[]
  onToggle: (analyzerId: string) => void
  className?: string
  renderAction?: (analyzerId: string) => ReactNode
}

export function AnalyzerChecklist({ idPrefix, selected, onToggle, className, renderAction }: Readonly<AnalyzerChecklistProps>) {
  return (
    <div className={cn('flex flex-col gap-2 border rounded-md p-4 overflow-y-auto', className)}>
      {Object.entries(ANALYZER_CATEGORIES).map(([categoryId, categoryInfo]) => {
        const categoryAnalyzers = AVAILABLE_ANALYZERS.filter((a) => a.category === categoryId)
        if (categoryAnalyzers.length === 0) return null

        return (
          <div key={categoryId} className="mb-3 last:mb-0">
            <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 pb-1 border-b">
              {categoryInfo.label}
            </div>
            {categoryAnalyzers.map((analyzer) => {
              const checked = selected.includes(analyzer.id)
              const hasRequiredDeps = !analyzer.dependsOn || analyzer.dependsOn.some((dep) => selected.includes(dep))
              const checkboxId = `${idPrefix}-${analyzer.id}`
              return (
                <div key={analyzer.id} className="flex items-start space-x-2 py-2">
                  <Checkbox id={checkboxId} checked={checked} onCheckedChange={() => onToggle(analyzer.id)} className="mt-1" />
                  <div className="flex flex-col gap-1 flex-1">
                    <div className="flex items-center gap-2">
                      <Label htmlFor={checkboxId} className="font-medium cursor-pointer">
                        {analyzer.label}
                      </Label>
                      {analyzer.isPostProcessor && (
                        <span className="text-[10px] px-1.5 py-0.5 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 rounded">
                          Post-Processor
                        </span>
                      )}
                      {analyzer.requiresCallgraph && (
                        <span className="text-[10px] px-1.5 py-0.5 bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 rounded">
                          Callgraph Required
                        </span>
                      )}
                      {renderAction?.(analyzer.id)}
                    </div>
                    <p className="text-xs text-muted-foreground">{analyzer.description}</p>
                    {analyzer.isPostProcessor && checked && !hasRequiredDeps && (
                      <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        Requires at least one vulnerability scanner to be enabled
                      </p>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )
      })}
    </div>
  )
}
