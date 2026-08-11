import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import type { TrendDirection } from '@/types/analytics'

export const TREND_CONFIG: Record<TrendDirection, { icon: typeof Minus; color: string; label: string }> = {
  improving: { icon: TrendingUp, color: 'text-green-500', label: 'Improving' },
  stable: { icon: Minus, color: 'text-gray-500', label: 'Stable' },
  deteriorating: { icon: TrendingDown, color: 'text-red-500', label: 'Deteriorating' },
  unknown: { icon: Minus, color: 'text-muted-foreground', label: 'Insufficient data' },
}
