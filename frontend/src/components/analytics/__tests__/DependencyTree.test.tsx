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

const READ = 10000;
const TOTAL = 42317;
const TRUNCATION_NOTE = /Built from/i;

function graph(nodes: DependencyTreeNode[], roots: string[], total = nodes.length): DependencyGraph {
  return { nodes, roots, dependencies_read: nodes.length, dependencies_total: total };
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
    renderTree(graph([node("a", { direct: true, child_ids: ["b"] }), node("b")], ["a"]));

    await screen.findByText("a");
    expect(screen.queryByText("b")).toBeNull(); // child not in the DOM until expanded
    expandRow("a");
    expect(await screen.findByText("b")).toBeInTheDocument();
  });

  it("renders a back-edge as a cycle leaf instead of recursing forever", async () => {
    renderTree(graph([node("a", { direct: true, child_ids: ["b"] }), node("b", { child_ids: ["a"] })], ["a"]));

    await screen.findByText("a");
    expandRow("a");
    await screen.findByText("b");
    expandRow("b"); // reveals a again — now an ancestor, so it must be a cycle leaf
    expect(await screen.findByText("cycle")).toBeInTheDocument();
  });

  it("counts direct vs transitive straight from the flat node list", async () => {
    renderTree(graph([node("a", { direct: true, child_ids: ["b"] }), node("b")], ["a"]));

    expect(await screen.findByText("1 direct dependencies")).toBeInTheDocument();
    expect(screen.getByText("1 transitive dependencies")).toBeInTheDocument();
  });

  it("says how much of the scan the tree was built from when the read was capped", async () => {
    renderTree({ nodes: [], roots: [], dependencies_read: READ, dependencies_total: TOTAL });

    expect(await screen.findByText(TRUNCATION_NOTE)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(TOTAL.toLocaleString()))).toBeInTheDocument();
  });

  it("stays quiet when the whole scan was read", async () => {
    renderTree(graph([node("a", { direct: true })], ["a"]));

    await screen.findByText("a");
    expect(screen.queryByText(TRUNCATION_NOTE)).toBeNull();
  });
});
