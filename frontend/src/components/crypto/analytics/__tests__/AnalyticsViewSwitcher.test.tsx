import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { MemoryRouter, useSearchParams } from "react-router-dom";

import { AnalyticsViewSwitcher } from "../AnalyticsViewSwitcher";

function Harness({ initial }: { initial: string }) {
  return (
    <MemoryRouter initialEntries={[`/?analytics_view=${initial}`]}>
      <AnalyticsViewSwitcher availableViews={["table", "heatmap", "treemap", "bar"]} />
      <ReadParams />
    </MemoryRouter>
  );
}

function ReadParams() {
  const [params] = useSearchParams();
  return <div data-testid="current-view">{params.get("analytics_view") ?? ""}</div>;
}

describe("AnalyticsViewSwitcher", () => {
  it("renders a button per view and reflects URL state", () => {
    render(<Harness initial="heatmap" />);
    expect(screen.getByTestId("current-view").textContent).toBe("heatmap");
    expect(screen.getByRole("button", { name: /table/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /heatmap/i })).toBeInTheDocument();
  });

  it("updates URL when a different view is clicked", () => {
    render(<Harness initial="table" />);
    fireEvent.click(screen.getByRole("button", { name: /treemap/i }));
    expect(screen.getByTestId("current-view").textContent).toBe("treemap");
  });
});
