import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import type { Finding } from "@/types/scan";
import { useProjectWaivers } from "@/hooks/queries/use-waivers";
import { WaiverForm } from "../WaiverForm";

vi.mock("@/api/waivers", () => ({
  waiverApi: {
    getByProject: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 50, pages: 1 })),
    create: vi.fn(async () => ({})),
  },
}));

import { waiverApi } from "@/api/waivers";

const FINDING = {
  id: "lodash:4.17.20",
  type: "vulnerability",
  severity: "HIGH",
  component: "lodash",
  version: "4.17.20",
  description: "",
  scanners: [],
  details: {},
  found_in: [],
  aliases: [],
  waived: false,
} as unknown as Finding;

function OpenWaiverList() {
  useProjectWaivers("p1");
  return null;
}

describe("WaiverForm", () => {
  it("refetches the project's open waiver list once after the waiver is created", async () => {
    const onSuccess = vi.fn();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <OpenWaiverList />
        <WaiverForm finding={FINDING} vulnId={null} projectId="p1" onCancel={() => {}} onSuccess={onSuccess} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(waiverApi.getByProject).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByPlaceholderText(/Why is this finding being ignored/i), { target: { value: "accepted" } });
    fireEvent.click(screen.getByRole("button", { name: /Confirm Waiver/i }));

    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    await waitFor(() => expect(client.isFetching()).toBe(0));
    expect(waiverApi.getByProject).toHaveBeenCalledTimes(2);
  });
});
