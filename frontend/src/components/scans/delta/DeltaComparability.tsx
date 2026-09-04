import type { ScanDeltaReachability, ScanDeltaResponse } from '@/types/scanDelta'

const NONE = 0
const FROM_LABEL = 'From'
const TO_LABEL = 'To'
const NO_REACHABILITY = 'no reachability'
const RISK_SCORES_INCOMPARABLE =
  'Only one side carries a callgraph, so only its risk scores are reachability-adjusted. '
  + 'Read the counts below; a risk-score change between these two scans measures the enrichment, not the code.'
const WAIVERS_DIVERGED =
  'The sides hide different numbers of waived findings, and waivers are re-evaluated only for the newest '
  + 'scan. Check the waiver list before treating an added finding as newly introduced — a waiver that '
  + 'lapsed since the older side makes a pre-existing finding read as added.'
const WAIVERS_HIDDEN =
  'Waived findings are hidden on both sides, so these totals sit below what the two scans themselves report.'

function reachabilityText(side: ScanDeltaReachability | null | undefined): string {
  if (!side) return NO_REACHABILITY
  return `reachability ${side.analyzed_count}/${side.coverable_count} analysed`
}

function sideText(
  reachability: ScanDeltaReachability | null | undefined,
  waived: number,
  showReachability: boolean,
  showWaived: boolean,
): string {
  const parts: string[] = []
  if (showReachability) parts.push(reachabilityText(reachability))
  if (showWaived) parts.push(`${waived} waived hidden`)
  return parts.join(' · ')
}

interface DeltaComparabilityProps {
  readonly delta: ScanDeltaResponse | null | undefined
}

export function DeltaComparability({ delta }: DeltaComparabilityProps) {
  if (!delta) return null

  const from = delta.from_reachability
  const to = delta.to_reachability
  const fromWaived = delta.from_waived_excluded
  const toWaived = delta.to_waived_excluded

  // Two scans that both report nothing have nothing to explain; the labels only earn their space
  // where one of the two channels actually differs from the plain reading of the counts.
  const showReachability = Boolean(from) || Boolean(to)
  const showWaived = fromWaived > NONE || toWaived > NONE
  if (!showReachability && !showWaived) return null

  const reachabilityDiverged = ((from?.analyzed_count ?? NONE) > NONE) !== ((to?.analyzed_count ?? NONE) > NONE)
  let waivedNote: string | null = null
  if (showWaived) waivedNote = fromWaived === toWaived ? WAIVERS_HIDDEN : WAIVERS_DIVERGED

  return (
    <div className="flex flex-col gap-1 rounded-md border border-dashed bg-muted/30 p-2 text-xs text-muted-foreground">
      <div className="flex flex-wrap gap-x-6 gap-y-1">
        <span>
          <span className="font-medium uppercase">{FROM_LABEL}</span>{' '}
          {sideText(from, fromWaived, showReachability, showWaived)}
        </span>
        <span>
          <span className="font-medium uppercase">{TO_LABEL}</span>{' '}
          {sideText(to, toWaived, showReachability, showWaived)}
        </span>
      </div>
      {reachabilityDiverged && <span>{RISK_SCORES_INCOMPARABLE}</span>}
      {waivedNote && <span>{waivedNote}</span>}
    </div>
  )
}
