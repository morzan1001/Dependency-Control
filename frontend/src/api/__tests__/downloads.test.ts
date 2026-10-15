import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AxiosError, type AxiosAdapter, type InternalAxiosRequestConfig } from "axios";
import { api } from "@/api/client";
import { getErrorMessage } from "@/lib/utils";
import { projectApi } from "@/api/projects";
import { inventoryApi } from "@/api/inventory";

const originalAdapter = api.defaults.adapter;
let sent: InternalAxiosRequestConfig[];

beforeEach(() => {
  sent = [];
  const adapter: AxiosAdapter = async (config) => {
    sent.push(config);
    return {
      data: new Blob(["x"]),
      status: 200,
      statusText: "OK",
      headers: { "content-disposition": 'attachment; filename="from-server.csv"' },
      config,
    };
  };
  api.defaults.adapter = adapter;
});

afterEach(() => {
  api.defaults.adapter = originalAdapter;
});

describe("file downloads", () => {
  it.each([
    ["archive", () => projectApi.downloadArchive("p1", "s1"), "/projects/p1/archives/s1/download", undefined],
    ["findings CSV", () => projectApi.exportCsv("p1"), "/projects/p1/export/csv", undefined],
    [
      "inventory CSV",
      () => inventoryApi.exportTable("p1", "components", "main"),
      "/projects/p1/inventory/components/export",
      { branch: "main" },
    ],
  ])("fetches the %s with no timeout under the server's filename", async (_, download, url, params) => {
    const file = await download();

    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe(url);
    expect(sent[0].params).toEqual(params);
    expect(sent[0].timeout).toBe(0);
    expect(file.filename).toBe("from-server.csv");
  });
});

describe("refused file downloads", () => {
  function refuseWith(status: number, body: string, type: string) {
    api.defaults.adapter = async (config) => {
      throw new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_REQUEST", config, null, {
        data: new Blob([body], { type }),
        status,
        statusText: "",
        headers: {},
        config,
      });
    };
  }

  it("hands the caller the reason the server gave, though the body came as a file", async () => {
    refuseWith(404, JSON.stringify({ detail: "Archive not found" }), "application/json");

    const error = await projectApi.downloadArchive("p1", "s1").catch((e: unknown) => e);

    expect(getErrorMessage(error)).toBe("Archive not found");
  });

  it("keeps the HTTP message when the refusal carries no JSON", async () => {
    refuseWith(502, "<html>Bad Gateway</html>", "text/html");

    const error = await projectApi.exportCsv("p1").catch((e: unknown) => e);

    expect(getErrorMessage(error)).toBe("Request failed with status code 502");
  });
});
