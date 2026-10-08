import { AlertCircle, FileX } from 'lucide-react'

export function InlineError({ message }: Readonly<{ message: string }>) {
  return (
    <div className="flex items-center gap-2 text-destructive text-sm">
      <AlertCircle className="h-4 w-4" />
      <span>{message}</span>
    </div>
  )
}

export function NoData({ entityName }: Readonly<{ entityName: string }>) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[200px] text-center p-6">
      <FileX className="h-12 w-12 text-muted-foreground/50 mb-4" />
      <h3 className="font-semibold text-lg mb-1">{`No ${entityName} found`}</h3>
      <p className="text-muted-foreground mb-4 max-w-md">{`There are no ${entityName} to display yet.`}</p>
    </div>
  )
}
