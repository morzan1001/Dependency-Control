import type { DeltaTruncation, ScanDeltaReachability, ScanDeltaResponse } from '@/types/scanDelta'

const NONE = 0
const FROM_LABEL = 'From'
const TO_LABEL = 'To'
const NO_REACHABILITY = 'no reachability'
const RISK_SCORES_INCOMPARABLE =
  'Only one side carries a callgraph, so only its risk scores are reachability-adjusted. '
  + 'Read the counts below; a risk-score change between these two scans measures the enrichment, not the code.'
const waiversDiverged = (count: number) =>
  `${count} of these changes are a waiver difference rather than a code difference: the finding is on `
  + 'both sides, waived on one. Waivers are re-evaluated only for the newest scan, so check the waiver '
  + 'list before treating an added finding as newly introduced.'
const WAIVERS_HIDDEN =
  'Waived findings are hidden on both sides, so these totals sit below what the two scans themselves report.'
const truncationText = (truncation: DeltaTruncation) =>
  `This comparison read ${truncation.from_compared.toLocaleString()} of ${truncation.from_total.toLocaleString()} `
  + `rows on the From side and ${truncation.to_compared.toLocaleString()} of ${truncation.to_total.toLocaleString()} `
  + `on the To side, a per-side cap of ${truncation.limit.toLocaleString()}. Both sides were read in the same order, `
  + 'so the totals below describe that window rather than the two scans: an item just past the cap on one side and '
  + 'inside it on the other is reported as added or removed. Filter by finding type or severity to bring a side '
  + 'under the cap.'

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
  // Equal counts hide unequal sets, so the warning keys on the changes a waiver actually explains.
  const waiverOnly = delta.waiver_only_changes
  const truncation = delta.truncation

  // Two scans that both report nothing have nothing to explain; the labels only earn their space
  // where one of the two channels actually differs from the plain reading of the counts.
  const showReachability = Boolean(from) || Boolean(to)
  const showWaived = fromWaived > NONE || toWaived > NONE
  if (!showReachability && !showWaived && !truncation) return null

  const reachabilityDiverged = ((from?.analyzed_count ?? NONE) > NONE) !== ((to?.analyzed_count ?? NONE) > NONE)
  let waivedNote: string | null = null
  if (waiverOnly > NONE) waivedNote = waiversDiverged(waiverOnly)
  else if (showWaived) waivedNote = WAIVERS_HIDDEN

  return (
    <div className="flex flex-col gap-1 rounded-md border border-dashed bg-muted/30 p-2 text-xs text-muted-foreground">
      {truncation && (
        <span className="font-medium text-amber-700 dark:text-amber-400">{truncationText(truncation)}</span>
      )}
      {(showReachability || showWaived) && (
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
      )}
      {reachabilityDiverged && <span>{RISK_SCORES_INCOMPARABLE}</span>}
      {waivedNote && <span>{waivedNote}</span>}
    </div>
  )
}
