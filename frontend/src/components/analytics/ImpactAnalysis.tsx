import { useQuery } from '@tanstack/react-query'
import { getImpactAnalysis, ImpactAnalysisResult } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Progress } from '@/components/ui/progress'
import { AlertTriangle, TrendingUp, Zap } from 'lucide-react'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

interface ImpactAnalysisProps {
  onSelectComponent?: (result: ImpactAnalysisResult) => void;
}

export function ImpactAnalysis({ onSelectComponent }: ImpactAnalysisProps) {
  const { data: results, isLoading } = useQuery({
    queryKey: ['impact-analysis'],
    queryFn: () => getImpactAnalysis(20),
  })

  // Calculate max impact score for relative sizing
  const maxImpact = results?.reduce((max, r) => Math.max(max, r.fix_impact_score), 0) || 1

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Zap className="h-5 w-5 text-yellow-500" />
          <div>
            <CardTitle>Impact Analysis</CardTitle>
            <CardDescription>
              Prioritized list of fixes - addressing these would have the greatest security impact
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array(5).fill(0).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : results && results.length > 0 ? (
          <div className="space-y-4">
            {/* Top 3 Priority Fixes */}
            <div className="grid gap-4 md:grid-cols-3">
              {results.slice(0, 3).map((r, index) => (
                <Card 
                  key={`${r.component}-${r.version}`}
                  className={`cursor-pointer transition-colors hover:bg-muted ${
                    index === 0 ? 'border-red-500 border-2' : 
                    index === 1 ? 'border-orange-500 border-2' : 
                    'border-yellow-500 border-2'
                  }`}
                  onClick={() => onSelectComponent?.(r)}
                >
                  <CardContent className="pt-4">
                    <div className="flex items-center justify-between mb-2">
                      <Badge variant={index === 0 ? "destructive" : "secondary"}>
                        #{index + 1} Priority
                      </Badge>
                      <div className="flex items-center gap-1 text-sm">
                        <TrendingUp className="h-4 w-4" />
                        <span className="font-medium">{Math.round(r.fix_impact_score)}</span>
                      </div>
                    </div>
                    <h4 className="font-medium truncate" title={r.component}>
                      {r.component}
                    </h4>
                    <p className="text-sm text-muted-foreground">v{r.version}</p>
                    <div className="flex items-center gap-2 mt-2 text-sm">
                      <span>{r.affected_projects} projects</span>
                      <span>•</span>
                      <span>{r.total_findings} findings</span>
                    </div>
                    <div className="flex gap-1 mt-2">
                      {r.findings_by_severity.critical > 0 && (
                        <Badge variant="destructive" className="text-xs">
                          {r.findings_by_severity.critical} Critical
                        </Badge>
                      )}
                      {r.findings_by_severity.high > 0 && (
                        <Badge className="text-xs bg-orange-500">
                          {r.findings_by_severity.high} High
                        </Badge>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Full Table */}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Component</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead className="text-center">Projects</TableHead>
                  <TableHead>Severity Breakdown</TableHead>
                  <TableHead>Impact Score</TableHead>
                  <TableHead>Affected Projects</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((r) => (
                  <TableRow 
                    key={`${r.component}-${r.version}`}
                    className={onSelectComponent ? "cursor-pointer hover:bg-muted" : ""}
                    onClick={() => onSelectComponent?.(r)}
                  >
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-destructive" />
                        <span className="font-medium">{r.component}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{r.version}</Badge>
                    </TableCell>
                    <TableCell className="text-center font-medium">
                      {r.affected_projects}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {r.findings_by_severity.critical > 0 && (
                          <Badge variant="destructive" className="text-xs">
                            C:{r.findings_by_severity.critical}
                          </Badge>
                        )}
                        {r.findings_by_severity.high > 0 && (
                          <Badge className="text-xs bg-orange-500 hover:bg-orange-600">
                            H:{r.findings_by_severity.high}
                          </Badge>
                        )}
                        {r.findings_by_severity.medium > 0 && (
                          <Badge className="text-xs bg-yellow-500 hover:bg-yellow-600 text-black">
                            M:{r.findings_by_severity.medium}
                          </Badge>
                        )}
                        {r.findings_by_severity.low > 0 && (
                          <Badge className="text-xs bg-blue-500 hover:bg-blue-600">
                            L:{r.findings_by_severity.low}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div className="w-32">
                              <Progress 
                                value={(r.fix_impact_score / maxImpact) * 100} 
                                className="h-2"
                              />
                              <span className="text-xs text-muted-foreground">
                                {Math.round(r.fix_impact_score)}
                              </span>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Impact score: {Math.round(r.fix_impact_score)}</p>
                            <p className="text-xs text-muted-foreground">
                              Weighted by severity × affected projects
                            </p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {r.affected_project_names.slice(0, 2).map((name) => (
                          <Badge key={name} variant="secondary" className="text-xs truncate max-w-[80px]">
                            {name}
                          </Badge>
                        ))}
                        {r.affected_project_names.length > 2 && (
                          <Badge variant="secondary" className="text-xs">
                            +{r.affected_project_names.length - 2}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Zap className="h-12 w-12 mb-4" />
            <p>No vulnerabilities found to analyze</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
