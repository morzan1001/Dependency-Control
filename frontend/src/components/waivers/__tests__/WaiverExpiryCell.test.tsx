import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { WaiverExpiryCell } from "../WaiverExpiryCell";
import type { Waiver } from "@/types/waiver";

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
  it("shows 'Never' when there is no expiration_date", () => {
    render(<WaiverExpiryCell waiver={makeWaiver({ expiration_date: undefined })} />);
    expect(screen.getByText(/Never/i)).toBeInTheDocument();
    expect(screen.queryByText(/Expired/i)).not.toBeInTheDocument();
  });

  it("shows the formatted date for an active waiver, no Expired badge", () => {
    render(
      <WaiverExpiryCell
        waiver={makeWaiver({ expiration_date: "2099-12-31T23:59:59.999Z", is_active: true })}
      />,
    );
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
