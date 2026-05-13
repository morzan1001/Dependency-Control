import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { DeltaList } from "../shared/DeltaList";

describe("DeltaList", () => {
  it("renders rows", () => {
    render(
      <DeltaList
        items={[
          { id: "1", primary: "foo" },
          { id: "2", primary: "bar" },
        ]}
        renderRow={(it) => <span>{it.primary}</span>}
        emptyMessage="nothing"
        isLoading={false}
      />,
    );
    expect(screen.getByText("foo")).toBeInTheDocument();
    expect(screen.getByText("bar")).toBeInTheDocument();
  });

  it("shows empty message when items is empty and not loading", () => {
    render(
      <DeltaList
        items={[]}
        renderRow={() => null}
        emptyMessage="nothing"
        isLoading={false}
      />,
    );
    expect(screen.getByText("nothing")).toBeInTheDocument();
  });

  it("shows skeleton when loading", () => {
    render(
      <DeltaList
        items={[]}
        renderRow={() => null}
        emptyMessage="nothing"
        isLoading={true}
      />,
    );
    expect(screen.getByTestId("delta-list-skeleton")).toBeInTheDocument();
  });
});
