// The API samples these lists server-side, so naming the remainder is the only way a reader can
// tell a complete list from the head of one.
export function withRemainder(shown: string[] | undefined, population: number | undefined): string {
  if (!shown?.length) return ''
  const hidden = (population ?? shown.length) - shown.length
  return hidden > 0 ? `${shown.join(', ')} (+${hidden} more)` : shown.join(', ')
}
