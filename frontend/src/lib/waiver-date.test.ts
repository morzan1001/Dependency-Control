import { describe, it, expect } from "vitest";
import { expirationDateInputToIso } from "./waiver-date";

describe("expirationDateInputToIso", () => {
  it("returns undefined for an empty input (no expiry)", () => {
    expect(expirationDateInputToIso("")).toBeUndefined();
  });

  it("returns undefined for null/undefined input", () => {
    expect(expirationDateInputToIso(undefined)).toBeUndefined();
    expect(expirationDateInputToIso(null)).toBeUndefined();
  });

  it("converts a date-input value to end-of-day UTC", () => {
    // A date input's day must stay active through its end, not expire at its midnight start.
    expect(expirationDateInputToIso("2026-05-08")).toBe("2026-05-08T23:59:59.999Z");
  });

  it("handles leap-day input correctly", () => {
    expect(expirationDateInputToIso("2028-02-29")).toBe("2028-02-29T23:59:59.999Z");
  });

  it("rejects malformed input by returning undefined", () => {
    expect(expirationDateInputToIso("not-a-date")).toBeUndefined();
    expect(expirationDateInputToIso("2026-13-01")).toBeUndefined();
  });
});
