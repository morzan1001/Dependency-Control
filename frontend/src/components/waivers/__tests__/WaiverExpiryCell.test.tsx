import { render, screen } from "@testing-library/react";
import { afterEach, describe, it, expect } from "vitest";
import { WaiverExpiryCell } from "../WaiverExpiryCell";
import { expirationDateInputToIso } from "@/lib/waiver-date";
import type { Waiver } from "@/types/waiver";

const ORIGINAL_TZ = process.env.TZ;

function makeWaiver(overrides: Partial<Waiver> = {}): Waiver {
  return {
    id: "w-1",
    reason: "test",
    status: "accepted_risk",
    created_at: "2026-01-01T00:00:00Z",
    created_by: "tester",
    is_active: true,
    ...overrides,
  };
}

describe("WaiverExpiryCell", () => {
  afterEach(() => {
    process.env.TZ = ORIGINAL_TZ;
  });

  it.each(["Europe/Berlin", "America/Los_Angeles"])("shows the day picked in the dialog to a browser in %s", (zone) => {
    process.env.TZ = zone;
    const picked = new Date(2027, 2, 31).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

    render(<WaiverExpiryCell waiver={makeWaiver({ expiration_date: expirationDateInputToIso("2027-03-31") })} />);

    expect(screen.getByText(picked)).toBeInTheDocument();
  });

  it("shows 'Never' when there is no expiration_date", () => {
    render(<WaiverExpiryCell waiver={makeWaiver({ expiration_date: undefined })} />);
    expect(screen.getByText(/Never/i)).toBeInTheDocument();
    expect(screen.queryByText(/Expired/i)).not.toBeInTheDocument();
  });

  it("renders an 'Expired' badge for inactive waivers", () => {
    render(
      <WaiverExpiryCell
        waiver={makeWaiver({ expiration_date: "2020-01-01T00:00:00Z", is_active: false })}
      />,
    );
    expect(screen.getByText(/Expired/i)).toBeInTheDocument();
  });
});
