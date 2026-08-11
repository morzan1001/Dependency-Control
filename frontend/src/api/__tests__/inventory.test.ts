import { describe, it, expect, vi, beforeEach } from "vitest";
import { inventoryApi } from "@/api/inventory";
import { api } from "@/api/client";

vi.mock("@/api/client", () => ({
  api: { get: vi.fn() },
}));

const mockedGet = api.get as unknown as ReturnType<typeof vi.fn>;

describe("inventoryApi", () => {
  beforeEach(() => vi.clearAllMocks());

  it("getStats hits the stats endpoint with the branch param", async () => {
    mockedGet.mockResolvedValue({ data: { components_total: 0 } });

    await inventoryApi.getStats("p1", "main");

    expect(mockedGet).toHaveBeenCalledWith("/projects/p1/inventory/stats", {
      params: { branch: "main" },
    });
  });

  it("getComponents applies default paging and sort params", async () => {
    mockedGet.mockResolvedValue({ data: { items: [] } });

    await inventoryApi.getComponents("p1", { branch: "main" });

    expect(mockedGet).toHaveBeenCalledWith("/projects/p1/inventory/components", {
      params: {
        branch: "main",
        page: 1,
        page_size: 25,
        search: undefined,
        sort_by: "name",
        sort_order: "asc",
      },
    });
  });

  it("getComponents passes through explicit search, paging and sort params", async () => {
    mockedGet.mockResolvedValue({ data: { items: [] } });

    await inventoryApi.getComponents("p1", {
      branch: "main",
      page: 3,
      pageSize: 50,
      search: "lodash",
      sortBy: "version",
      sortOrder: "desc",
    });

    expect(mockedGet).toHaveBeenCalledWith("/projects/p1/inventory/components", {
      params: {
        branch: "main",
        page: 3,
        page_size: 50,
        search: "lodash",
        sort_by: "version",
        sort_order: "desc",
      },
    });
  });

  it("getLicenses hits the licenses endpoint with the branch param", async () => {
    mockedGet.mockResolvedValue({ data: { items: [] } });

    await inventoryApi.getLicenses("p1", "main");

    expect(mockedGet).toHaveBeenCalledWith("/projects/p1/inventory/licenses", {
      params: { branch: "main" },
    });
  });

  it("getCrypto applies default paging params", async () => {
    mockedGet.mockResolvedValue({ data: { items: [] } });

    await inventoryApi.getCrypto("p1", { branch: "main" });

    expect(mockedGet).toHaveBeenCalledWith("/projects/p1/inventory/crypto", {
      params: { branch: "main", page: 1, page_size: 25 },
    });
  });

  it.each(["components", "licenses", "crypto"] as const)(
    "exportTable requests %s as a blob with the branch param",
    async (table) => {
      const blob = new Blob(["csv"]);
      mockedGet.mockResolvedValue({ data: blob });

      const result = await inventoryApi.exportTable("p1", table, "main");

      expect(mockedGet).toHaveBeenCalledWith(`/projects/p1/inventory/${table}/export`, {
        params: { branch: "main" },
        responseType: "blob",
      });
      expect(result).toBe(blob);
    },
  );
});
