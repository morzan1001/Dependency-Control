import type { ReactNode } from 'react'
import { ArrowDown, ArrowUp } from 'lucide-react'

import { TableHead } from '@/components/ui/table'
import type { SortOrder, SortState } from '@/hooks/use-pagination-state'
import { cn } from '@/lib/utils'

interface SortableHeadProps<T extends string> {
  column: T
  sort: SortState<T>
  firstOrder?: SortOrder
  className?: string
  children: ReactNode
}

export function SortableHead<T extends string>({ column, sort, firstOrder, className, children }: Readonly<SortableHeadProps<T>>) {
  const active = sort.sortBy === column
  const Arrow = sort.sortOrder === 'asc' ? ArrowUp : ArrowDown
  return (
    <TableHead
      className={cn('cursor-pointer hover:text-foreground', className)}
      aria-sort={active ? (sort.sortOrder === 'asc' ? 'ascending' : 'descending') : undefined}
      onClick={() => sort.toggleSort(column, firstOrder)}
    >
      {children}
      {active && <Arrow className="ml-2 h-4 w-4 inline" />}
    </TableHead>
  )
}
