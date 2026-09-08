import { createContext, useContext } from 'react'

// Undefined is head mode, so a component rendered outside the analytics page reports the branch tip.
export const AnalyticsModeContext = createContext<string | undefined>(undefined)

export function useAnalyticsMode(): string | undefined {
  return useContext(AnalyticsModeContext)
}
