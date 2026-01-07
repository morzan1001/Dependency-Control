import { useState } from 'react'
import { useSearchDependencies } from '@/hooks/queries/use-analytics'
import { SearchResult } from '@/types/analytics'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Search as SearchIcon, Package } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { Link } from 'react-router-dom'

export default function SearchPage() {
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  const { data: results, isLoading } = useSearchDependencies(debouncedQuery)

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setDebouncedQuery(query)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dependency Search</h1>
        <p className="text-muted-foreground">
          Search for dependencies across all projects.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Search</CardTitle>
          <CardDescription>
            Enter a package name to find where it is used.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSearch} className="flex gap-2">
            <Input 
              placeholder="e.g. react, lodash, requests" 
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <Button type="submit">
              <SearchIcon className="mr-2 h-4 w-4" />
              Search
            </Button>
          </form>
        </CardContent>
      </Card>

      {isLoading && (
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-24 mb-2" />
            <Skeleton className="h-4 w-48" />
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          </CardContent>
        </Card>
      )}

      {results && (
        <Card>
          <CardHeader>
            <CardTitle>Results</CardTitle>
            <CardDescription>
              Found {results.length} occurrences.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-auto">Project</TableHead>
                  <TableHead className="w-[200px]">Package</TableHead>
                  <TableHead className="w-[150px]">Version</TableHead>
                  <TableHead className="w-[100px]">Type</TableHead>
                  <TableHead className="w-[150px]">License</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((result: SearchResult, index: number) => (
                  <TableRow key={index}>
                    <TableCell>
                      <Link to={`/projects/${result.project_id}`} className="hover:underline font-medium flex items-center gap-2">
                        <Package className="h-4 w-4" />
                        {result.project_name}
                      </Link>
                    </TableCell>
                    <TableCell>{result.package}</TableCell>
                    <TableCell>{result.version}</TableCell>
                    <TableCell>{result.type}</TableCell>
                    <TableCell>{result.license || 'Unknown'}</TableCell>
                  </TableRow>
                ))}
                {results.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      No results found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
