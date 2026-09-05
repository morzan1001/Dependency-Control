import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import type { DependencyGraph } from "@/types/analytics";

const READ = 10000;
const TOTAL = 42317;
const TRUNCATION_NOTE = /Built from/i;

const graphRef: { current: DependencyGraph } = {
  current: { nodes: [], roots: [], dependencies_read: TOTAL, dependencies_total: TOTAL },
};

vi.mock("@/hooks/queries/use-analytics", () => ({
  useDependencyTree: () => ({ data: graphRef.current, isLoading: false }),
}));
vi.mock("@/components/ui/project-combobox", () => ({
  ProjectCombobox: () => null,
}));

import { DependencyTree } from "../DependencyTree";

function renderTree(graph: DependencyGraph) {
  graphRef.current = graph;
  return render(<DependencyTree />);
}

describe("DependencyTree dependency coverage", () => {
  it("says how much of the scan the tree was built from when the read was capped", () => {
    renderTree({ nodes: [], roots: [], dependencies_read: READ, dependencies_total: TOTAL });

    expect(screen.getByText(TRUNCATION_NOTE)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(TOTAL.toLocaleString()))).toBeInTheDocument();
  });

  it("stays quiet when the whole scan was read", () => {
    renderTree({ nodes: [], roots: [], dependencies_read: TOTAL, dependencies_total: TOTAL });

    expect(screen.queryByText(TRUNCATION_NOTE)).not.toBeInTheDocument();
  });
});
