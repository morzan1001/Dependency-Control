// End of the picked day in UTC, so "expires on the 8th" holds through the 8th.
export function expirationDateInputToIso(date: string | null | undefined): string | undefined {
  if (!date) return undefined;
  const parsed = new Date(`${date}T23:59:59.999Z`);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}
