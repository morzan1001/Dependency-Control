import { useMemo, useState } from 'react'
import { useDependencyTree } from '@/hooks/queries/use-analytics'
import { DependencyTreeNode } from '@/types/analytics'
import { flattenUniqueDependencies } from '@/lib/dependency-tree-utils'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { ProjectCombobox } from '@/components/ui/project-combobox'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { ChevronRight, ChevronDown, Package, AlertTriangle, Shield, Layers } from 'lucide-react'
import { cn } from '@/lib/utils'
import { getSourceInfo } from '@/lib/finding-utils'

interface DependencyNodeProps {
  node: DependencyTreeNode;
  level: number;
  onSelect?: (node: DependencyTreeNode) => void;
  hideChildren?: boolean;
}

const DEP_TREE_SKELETON_IDS = ['dt1', 'dt2', 'dt3', 'dt4', 'dt5', 'dt6', 'dt7', 'dt8']

function DependencyNode({ node, level, onSelect, hideChildren }: Readonly<DependencyNodeProps>) {
  const [isExpanded, setIsExpanded] = useState(false)
  const hasChildren = !hideChildren && !!node.children && node.children.length > 0
  const sourceInfo = getSourceInfo(node.source_type)

  const getSeverityBorder = () => {
    if (!node.findings_severity) return ''
    if (node.findings_severity.critical > 0) return 'border-l-red-500'
    if (node.findings_severity.high > 0) return 'border-l-orange-500'
    if (node.findings_severity.medium > 0) return 'border-l-yellow-500'
    if (node.findings_severity.low > 0) return 'border-l-blue-500'
    return ''
  }

  return (
      <div>
        <div
          className={cn(
            "flex items-center gap-2 py-2 px-3 hover:bg-muted rounded-lg cursor-pointer border-l-4",
            node.has_findings ? getSeverityBorder() : "border-l-transparent",
          )}
          role="treeitem"
          aria-selected={false}
          tabIndex={0}
          style={{ paddingLeft: `${level * 24 + 12}px` }}
          onClick={() => onSelect?.(node)}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect?.(node); } }}
        >
          {hasChildren && (
            <Button
              variant="ghost"
              size="icon"
              className="h-5 w-5"
              onClick={(e: React.MouseEvent) => {
                e.stopPropagation()
                setIsExpanded(!isExpanded)
              }}
            >
              {isExpanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </Button>
          )}
          {!hasChildren && <div className="w-5" />}
          
          <Package className="h-4 w-4 text-muted-foreground" />
          
          <div className="flex-1 flex items-center gap-2">
            <span className="font-medium">{node.name}</span>
            <Badge variant="outline" className="text-xs">{node.version}</Badge>
            {node.direct && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge variant="secondary" className="text-xs cursor-help">
                    direct{node.direct_inferred ? '*' : ''}
                  </Badge>
                </TooltipTrigger>
                {node.direct_inferred && (
                  <TooltipContent side="top">
                    <p className="text-xs">
                      Direct/transitive classification inferred (SBOM had no dependency graph)
                    </p>
                  </TooltipContent>
                )}
              </Tooltip>
            )}

            {sourceInfo && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex items-center gap-1">
                    <sourceInfo.icon className={cn("h-4 w-4", sourceInfo.color)} />
                  </div>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs">
                  <div className="space-y-1">
                    <p className="font-medium">{sourceInfo.label}</p>
                    {node.source_target && (
                      <p className="text-xs text-muted-foreground break-all">{node.source_target}</p>
                    )}
                    {node.layer_digest && node.layer_digest.length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        Layer: {node.layer_digest.length > 20 ? `${node.layer_digest.substring(0, 20)}...` : node.layer_digest}
                      </p>
                    )}
                    {node.locations && node.locations.length > 0 && (
                      <div className="text-xs text-muted-foreground">
                        <p>Locations:</p>
                        {node.locations.slice(0, 3).map((loc) => (
                          <p key={loc} className="pl-2 truncate">{loc}</p>
                        ))}
                        {node.locations.length > 3 && (
                          <p className="pl-2">+{node.locations.length - 3} more</p>
                        )}
                      </div>
                    )}
                  </div>
                </TooltipContent>
              </Tooltip>
            )}
          </div>
          
          <Badge variant="secondary" className="text-xs">{node.type}</Badge>
          
          {node.has_findings && (
            <div className="flex items-center gap-1">
              <AlertTriangle className="h-4 w-4 text-destructive" />
              <span className="text-sm text-destructive">{node.findings_count}</span>
            </div>
          )}
        </div>
        
        {isExpanded && hasChildren && (
          <div>
            {node.children.map((child) => (
              <DependencyNode
                key={child.id}
                node={child}
                level={level + 1}
                onSelect={onSelect}
              />
            ))}
          </div>
        )}
      </div>
  )
}

interface DependencyTreeProps {
  onSelectNode?: (node: DependencyTreeNode) => void;
}

export function DependencyTree({ onSelectNode }: Readonly<DependencyTreeProps>) {
  const [selectedProjectId, setSelectedProjectId] = useState<string>('')
  const [showDirectOnly, setShowDirectOnly] = useState(false)

  const { data: tree, isLoading: isLoadingTree } = useDependencyTree(selectedProjectId)

  // Roots are the direct dependencies (transitive deps are nested inside them). Transitive
  // deps whose parent could not be resolved come back as flat top-level nodes.
  const directRoots = tree?.filter(n => n.direct) ?? []
  const orphanTransitive = tree?.filter(n => !n.direct) ?? []

  // Counts walk the whole tree deduplicated: a transitive dep nested under several parents
  // must be counted once, and nested deps must be counted at all.
  const uniqueDeps = useMemo(() => flattenUniqueDependencies(tree), [tree])
  const directCount = uniqueDeps.filter(n => n.direct).length
  const transitiveCount = uniqueDeps.filter(n => !n.direct).length
  const vulnerableCount = uniqueDeps.filter(n => n.has_findings).length
  const hasDependencies = (tree?.length ?? 0) > 0

  return (
    <TooltipProvider>
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Dependency Tree</CardTitle>
            <CardDescription>View dependencies and their relationship to vulnerabilities</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <ProjectCombobox 
              value={selectedProjectId} 
              onValueChange={setSelectedProjectId}
              className="w-[300px]"
            />
            <Button
              variant={showDirectOnly ? "default" : "outline"}
              size="sm"
              onClick={() => setShowDirectOnly(!showDirectOnly)}
            >
              <Layers className="h-4 w-4 mr-2" />
              Direct only
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {(() => {
          if (!selectedProjectId) {
            return (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Package className="h-12 w-12 mb-4" />
                <p>Select a project to view its dependency tree</p>
              </div>
            )
          }
          if (isLoadingTree) {
            return (
              <div className="space-y-2">
                {DEP_TREE_SKELETON_IDS.map((id) => (
                  <Skeleton key={id} className="h-10 w-full" />
                ))}
              </div>
            )
          }
          if (hasDependencies) {
            return (
            <div className="space-y-4">
              <div className="flex items-center gap-4 p-4 bg-muted rounded-lg">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-green-500" />
                  <span className="text-sm font-medium">
                    {directCount} direct dependencies
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Layers className="h-5 w-5 text-blue-500" />
                  <span className="text-sm font-medium">
                    {transitiveCount} transitive dependencies
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-destructive" />
                  <span className="text-sm font-medium">
                    {vulnerableCount} with vulnerabilities
                  </span>
                </div>
              </div>

              {directRoots.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-2">Direct Dependencies</h4>
                  <div className="border rounded-lg divide-y">
                    {directRoots.map((node) => (
                      <DependencyNode
                        key={node.id}
                        node={node}
                        level={0}
                        onSelect={onSelectNode}
                        hideChildren={showDirectOnly}
                      />
                    ))}
                  </div>
                </div>
              )}

              {!showDirectOnly && orphanTransitive.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-2">Transitive Dependencies</h4>
                  <p className="text-xs text-muted-foreground mb-2">
                    Not linked to a parent package (SBOM had no dependency graph, or its parents use a non-PURL identifier).
                  </p>
                  <div className="border rounded-lg divide-y max-h-[400px] overflow-y-auto">
                    {orphanTransitive.map((node) => (
                      <DependencyNode
                        key={node.id}
                        node={node}
                        level={0}
                        onSelect={onSelectNode}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
            )
          }
          return (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Package className="h-12 w-12 mb-4" />
              <p>No dependencies found for this project</p>
            </div>
          )
        })()}
      </CardContent>
    </Card>
    </TooltipProvider>
  )
}
