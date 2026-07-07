// Convert an `<input type="date">` value to an end-of-day UTC ISO timestamp, so
// "expires on the 8th" still works through the 8th rather than expiring at its
// start. Returns undefined for empty/invalid input.
export function expirationDateInputToIso(date: string | null | undefined): string | undefined {
  if (!date) return undefined;
  const parsed = new Date(`${date}T23:59:59.999Z`);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}
