import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import type { ImpactAnalysisResult } from "@/types/analytics";
import { ImpactAnalysis } from "../ImpactAnalysis";

vi.mock("@/api/analytics", () => ({
  analyticsApi: { getImpactAnalysis: vi.fn() },
}));

import { analyticsApi } from "@/api/analytics";

function renderImpact() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ImpactAnalysis />
    </QueryClientProvider>,
  );
}

describe("ImpactAnalysis fix versions", () => {
  const SAMPLED = ["3.0.0", "2.5.0", "2.4.1"];
  const result: ImpactAnalysisResult = {
    component: "lodash",
    version: "1.0.0",
    affected_projects: 2,
    total_findings: 4,
    findings_by_severity: { critical: 1, high: 1, medium: 1, low: 1 },
    fix_impact_score: 50,
    affected_project_names: ["a", "b"],
    has_fix: true,
    fix_versions: SAMPLED,
    fix_version_count: 5,
  };

  it("says the fix versions in the card and the table are a sample of more", async () => {
    vi.mocked(analyticsApi.getImpactAnalysis).mockResolvedValue([result]);
    const { container } = renderImpact();

    fireEvent.focus(await screen.findByText("Fix available"));
    expect(await screen.findByRole("tooltip")).toHaveTextContent(`Fix versions: ${SAMPLED.join(", ")} (+2 more)`);

    fireEvent.blur(screen.getByText("Fix available"));
    fireEvent.focus(container.querySelector("td .text-success")!);
    expect(await screen.findByRole("tooltip")).toHaveTextContent(`Fix versions: ${SAMPLED.join(", ")} (+2 more)`);
  });

  it("breaks each component's findings down by severity in the table, in the severity pill colours", async () => {
    vi.mocked(analyticsApi.getImpactAnalysis).mockResolvedValue([
      { ...result, findings_by_severity: { critical: 1, high: 2, medium: 3, low: 0 } },
    ]);
    renderImpact();

    expect(await screen.findByText("C:1")).toHaveClass("text-xs", "bg-severity-critical", "text-severity-critical-foreground");
    expect(screen.getByText("H:2")).toHaveClass("text-xs", "bg-severity-high", "text-severity-high-foreground");
    expect(screen.getByText("M:3")).toHaveClass("text-xs", "bg-severity-medium", "text-severity-medium-foreground");
    expect(screen.queryByText(/^L:/)).not.toBeInTheDocument();
  });

  it("counts a top component's critical and high findings on its card in the severity pill colours", async () => {
    vi.mocked(analyticsApi.getImpactAnalysis).mockResolvedValue([
      { ...result, findings_by_severity: { critical: 1, high: 2, medium: 3, low: 0 } },
    ]);
    renderImpact();

    expect(await screen.findByText("1 Critical")).toHaveClass("text-xs", "bg-severity-critical", "text-severity-critical-foreground");
    expect(screen.getByText("2 High")).toHaveClass("text-xs", "bg-severity-high", "text-severity-high-foreground");
  });

  it("writes a Go module's version once, as the findings table does, not as vv0.3.0", async () => {
    vi.mocked(analyticsApi.getImpactAnalysis).mockResolvedValue([{ ...result, component: "golang.org/x/text", version: "v0.3.0" }]);
    renderImpact();

    expect((await screen.findAllByText("v0.3.0")).length).toBeGreaterThan(0);
    expect(screen.queryByText("vv0.3.0")).not.toBeInTheDocument();
  });
});

describe("ImpactAnalysis load error", () => {
  it("says the request failed instead of reporting nothing to analyze", async () => {
    vi.mocked(analyticsApi.getImpactAnalysis).mockRejectedValue(
      Object.assign(new Error("Request failed"), { response: { status: 403, data: { detail: "Not enough permissions" } } }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    render(
      <QueryClientProvider client={client}>
        <ImpactAnalysis />
      </QueryClientProvider>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Not enough permissions");
    expect(screen.queryByText("No vulnerabilities found to analyze")).not.toBeInTheDocument();
  });
});
