/**
 * Convert the value of a `<input type="date">` (e.g. "2026-05-08") into an
 * ISO timestamp the backend stores. End-of-day UTC, not midnight, because the
 * user's mental model of "expires on the 8th" is "still works through the
 * 8th", but `new Date("2026-05-08").toISOString()` resolves to
 * 2026-05-08T00:00:00Z — which expires the waiver at the *start* of that day.
 *
 * Returns `undefined` for empty / invalid input so callers can pass
 * `expiration_date: expirationDateInputToIso(date)` straight through to
 * the API request body.
 */
export function expirationDateInputToIso(date: string | null | undefined): string | undefined {
  if (!date) return undefined;
  // Validate strictly — `new Date("not-a-date")` returns Invalid Date.
  const parsed = new Date(`${date}T23:59:59.999Z`);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return parsed.toISOString();
}
