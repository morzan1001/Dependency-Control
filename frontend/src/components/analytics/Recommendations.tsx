import { useState } from 'react'
import { useProjectRecommendations } from '@/hooks/queries/use-analytics'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ProjectCombobox } from '@/components/ui/project-combobox'
import { Lightbulb, Shield, ShieldAlert } from 'lucide-react'
import { RecommendationCard } from './recommendations/RecommendationCard'
import { SummaryCard } from './recommendations/SummaryCard'

interface RecommendationsProps {
  projectId?: string
  scanId?: string
}

export function Recommendations({ projectId: initialProjectId, scanId }: RecommendationsProps) {
  const [selectedProjectId, setSelectedProjectId] = useState<string>(initialProjectId || '')

  const { data, isLoading, error } = useProjectRecommendations(selectedProjectId, scanId)

  return (
    <div className="space-y-6">
      {/* Project Selector */}
      {!initialProjectId && (
        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
            <CardDescription>
              Get actionable remediation recommendations for your project's vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <ProjectCombobox
                value={selectedProjectId}
                onValueChange={setSelectedProjectId}
                className="w-[350px]"
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {isLoading && selectedProjectId && (
        <div className="space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      )}

      {/* Error State */}
      {error && (
        <Card>
          <CardContent className="py-8">
            <div className="flex flex-col items-center gap-2 text-muted-foreground">
              <ShieldAlert className="h-12 w-12" />
              <p>Failed to load recommendations</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!selectedProjectId && !initialProjectId && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4 text-muted-foreground">
              <Lightbulb className="h-12 w-12" />
              <p>Select a project to view remediation recommendations</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {data && (
        <>
          {/* Summary */}
          <SummaryCard data={data} />

          {/* Recommendations List */}
          {data.recommendations.length > 0 ? (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">
                {data.recommendations.length} Recommendations
              </h3>
              {data.recommendations.map((rec) => (
                <RecommendationCard key={`${rec.type}-${rec.title}`} recommendation={rec} />
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12">
                <div className="flex flex-col items-center gap-4 text-muted-foreground">
                  <Shield className="h-12 w-12 text-success" />
                  <p className="text-lg font-medium text-foreground">No vulnerabilities found!</p>
                  <p>This project has no known vulnerabilities to remediate.</p>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
