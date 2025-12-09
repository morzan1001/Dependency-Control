import { Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

export interface SpinnerProps extends React.SVGAttributes<SVGElement> {
  size?: number
}

export function Spinner({ className, size = 24, ...props }: SpinnerProps) {
  return (
    <Loader2 
      className={cn("animate-spin text-primary", className)} 
      size={size} 
      {...props} 
    />
  )
}
