import { useState } from 'react'
import { useDependencyTree } from '@/hooks/queries/use-analytics'
import { DependencyTreeNode } from '@/types/analytics'
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
}

function DependencyNode({ node, level, onSelect }: DependencyNodeProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const hasChildren = node.children && node.children.length > 0
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
    <TooltipProvider>
      <div>
        <div
          className={cn(
            "flex items-center gap-2 py-2 px-3 hover:bg-muted rounded-lg cursor-pointer border-l-4",
            node.has_findings ? getSeverityBorder() : "border-l-transparent",
          )}
          style={{ paddingLeft: `${level * 24 + 12}px` }}
          onClick={() => onSelect?.(node)}
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
            
            {/* Source information */}
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
                        {node.locations.slice(0, 3).map((loc, i) => (
                          <p key={i} className="pl-2 truncate">{loc}</p>
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
    </TooltipProvider>
  )
}

interface DependencyTreeProps {
  onSelectNode?: (node: DependencyTreeNode) => void;
}

export function DependencyTree({ onSelectNode }: DependencyTreeProps) {
  const [selectedProjectId, setSelectedProjectId] = useState<string>('')
  const [showDirectOnly, setShowDirectOnly] = useState(false)

  const { data: tree, isLoading: isLoadingTree } = useDependencyTree(selectedProjectId)

  const filteredTree = showDirectOnly 
    ? tree?.filter(n => n.direct) 
    : tree

  // Separate direct and transitive for display
  const directDeps = filteredTree?.filter(n => n.direct) || []
  const transitiveDeps = filteredTree?.filter(n => !n.direct) || []

  return (
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
        {!selectedProjectId ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Package className="h-12 w-12 mb-4" />
            <p>Select a project to view its dependency tree</p>
          </div>
        ) : isLoadingTree ? (
          <div className="space-y-2">
            {new Array(8).fill(0).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : filteredTree && filteredTree.length > 0 ? (
          <div className="space-y-4">
            {/* Summary */}
            <div className="flex items-center gap-4 p-4 bg-muted rounded-lg">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-green-500" />
                <span className="text-sm font-medium">
                  {directDeps.length} direct dependencies
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Layers className="h-5 w-5 text-blue-500" />
                <span className="text-sm font-medium">
                  {transitiveDeps.length} transitive dependencies
                </span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <span className="text-sm font-medium">
                  {filteredTree.filter(n => n.has_findings).length} with vulnerabilities
                </span>
              </div>
            </div>

            {/* Direct Dependencies Section */}
            {directDeps.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-muted-foreground mb-2">Direct Dependencies</h4>
                <div className="border rounded-lg divide-y">
                  {directDeps.map((node) => (
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

            {/* Transitive Dependencies Section */}
            {!showDirectOnly && transitiveDeps.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-muted-foreground mb-2">Transitive Dependencies</h4>
                <div className="border rounded-lg divide-y max-h-[400px] overflow-y-auto">
                  {transitiveDeps.map((node) => (
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
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Package className="h-12 w-12 mb-4" />
            <p>No dependencies found for this project</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
