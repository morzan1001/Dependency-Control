import { describe, it, expect } from "vitest";

import { withRemainder } from "../sampled-list";

const SHOWN = ["CVE-2026-1", "CVE-2026-2"];
const LARGER_POPULATION = 5;
const HIDDEN = LARGER_POPULATION - SHOWN.length;

describe("withRemainder", () => {
  it("names how many the sample left out", () => {
    expect(withRemainder(SHOWN, LARGER_POPULATION)).toBe(`${SHOWN.join(", ")} (+${HIDDEN} more)`);
  });

  it("says nothing extra when the sample is the whole population", () => {
    expect(withRemainder(SHOWN, SHOWN.length)).toBe(SHOWN.join(", "));
  });

  it("treats an absent population as the sample itself", () => {
    expect(withRemainder(SHOWN, undefined)).toBe(SHOWN.join(", "));
  });

  it("renders nothing for an empty sample", () => {
    expect(withRemainder([], LARGER_POPULATION)).toBe("");
  });
});
