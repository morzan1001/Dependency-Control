import { render, screen, within, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { DependencyGraph, DependencyTreeNode } from "@/types/analytics";
import { DependencyTree } from "../DependencyTree";

vi.mock("@/api/analytics", () => ({
  analyticsApi: { getDependencyTree: vi.fn() },
}));

// The tree only renders once a project is picked; stub the combobox to select one immediately.
vi.mock("@/components/ui/project-combobox", () => ({
  ProjectCombobox: ({ onValueChange }: { onValueChange: (v: string) => void }) => (
    <button type="button" onClick={() => onValueChange("p1")}>select-project</button>
  ),
}));

import { analyticsApi } from "@/api/analytics";

const getTree = analyticsApi.getDependencyTree as ReturnType<typeof vi.fn>;

function node(id: string, over: Partial<DependencyTreeNode> = {}): DependencyTreeNode {
  return {
    id,
    name: id,
    version: "1.0.0",
    purl: `pkg:pypi/${id}@1.0.0`,
    type: "pypi",
    direct: false,
    has_findings: false,
    findings_count: 0,
    child_ids: [],
    ...over,
  };
}

function renderTree(graph: DependencyGraph): void {
  getTree.mockResolvedValue(graph);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <DependencyTree />
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByText("select-project"));
}

function expandRow(name: string): void {
  const row = screen.getByText(name).closest('[role="treeitem"]') as HTMLElement;
  fireEvent.click(within(row).getByRole("button"));
}

describe("DependencyTree lazy expansion + cycle handling", () => {
  beforeEach(() => getTree.mockReset());

  it("resolves child_ids from the node map only on expand (lazy render)", async () => {
    renderTree({ nodes: [node("a", { direct: true, child_ids: ["b"] }), node("b")], roots: ["a"] });

    await screen.findByText("a");
    expect(screen.queryByText("b")).toBeNull(); // child not in the DOM until expanded
    expandRow("a");
    expect(await screen.findByText("b")).toBeInTheDocument();
  });

  it("renders a back-edge as a cycle leaf instead of recursing forever", async () => {
    renderTree({
      nodes: [node("a", { direct: true, child_ids: ["b"] }), node("b", { child_ids: ["a"] })],
      roots: ["a"],
    });

    await screen.findByText("a");
    expandRow("a");
    await screen.findByText("b");
    expandRow("b"); // reveals a again — now an ancestor, so it must be a cycle leaf
    expect(await screen.findByText("cycle")).toBeInTheDocument();
  });

  it("counts direct vs transitive straight from the flat node list", async () => {
    renderTree({ nodes: [node("a", { direct: true, child_ids: ["b"] }), node("b")], roots: ["a"] });

    expect(await screen.findByText("1 direct dependencies")).toBeInTheDocument();
    expect(screen.getByText("1 transitive dependencies")).toBeInTheDocument();
  });
});
