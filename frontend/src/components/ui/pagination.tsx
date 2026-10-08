import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface PaginationProps {
  page: number
  totalPages: number
  onChange: (page: number) => void
  total?: number
  nextDisabled?: boolean
}

export function Pagination({ page, totalPages, onChange, total, nextDisabled }: Readonly<PaginationProps>) {
  if (totalPages <= 1) return null
  return (
    <div className="flex items-center justify-end gap-2 py-4 text-sm text-muted-foreground">
      Page {page} of {totalPages}{total !== undefined && ` (${total} total)`}
      <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onChange(page - 1)}>
        <ChevronLeft className="h-4 w-4" /> Previous
      </Button>
      <Button variant="outline" size="sm" disabled={page >= totalPages || nextDisabled} onClick={() => onChange(page + 1)}>
        Next <ChevronRight className="h-4 w-4" />
      </Button>
    </div>
  )
}
