import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Permissions } from "@/lib/permissions";
import type {
  ApiKey,
  ApiKeyCreateResponse,
  ApiKeyListResponse,
} from "@/types/apiKey";

import { ApiKeysCard } from "../ApiKeysCard";

const NOW = "2026-09-10T12:00:00Z";
const CREATED_AT = "2026-09-01T12:00:00Z";
const EXPIRES_AT = "2026-12-09T12:00:00Z";
const LAST_USED_AT = "2026-09-07T12:00:00Z";
const MCP_KEY_ID = "k-mcp";
const ADHOC_KEY_ID = "k-adhoc";
const DAMAGED_KEY_ID = "k-damaged";
const MCP_KEY_NAME = "claude desktop";
const ADHOC_KEY_NAME = "release pipeline";
const MCP_PREFIX = "dck_abcdefgh";
const ADHOC_PREFIX = "dck_ijklmnop";
const PLAINTEXT_TOKEN = "dck_a-token-shown-exactly-once";
const SURFACE_REFUSED =
  "Permission 'mcp:access' is required for the 'mcp' surface";
const DEFAULT_EXPIRY_DAYS = 90;
const LIST_PAGE = 100;
const TOTAL_KEYS = 103;
const NOT_CALLED = 0;
const CALLED_ONCE = 1;
const SHOWN_ONCE = 1;
const NONE = 0;

const { listKeys, createKey, revokeKey, granted, toastError, toastSuccess } =
  vi.hoisted(() => ({
    listKeys: vi.fn(),
    createKey: vi.fn(),
    revokeKey: vi.fn(),
    granted: { current: [] as string[] },
    toastError: vi.fn(),
    toastSuccess: vi.fn(),
  }));

vi.mock("@/api/apiKeys", () => ({
  apiKeysApi: { list: listKeys, create: createKey, revoke: revokeKey },
}));

vi.mock("@/context", () => ({
  useAuth: () => ({
    hasPermission: (permission: string) => granted.current.includes(permission),
  }),
}));

vi.mock("sonner", () => ({
  toast: { error: toastError, success: toastSuccess },
}));

const mcpKey: ApiKey = {
  id: MCP_KEY_ID,
  name: MCP_KEY_NAME,
  prefix: MCP_PREFIX,
  surfaces: ["mcp"],
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
  last_used_at: LAST_USED_AT,
};

const adhocKey: ApiKey = {
  id: ADHOC_KEY_ID,
  name: ADHOC_KEY_NAME,
  prefix: ADHOC_PREFIX,
  surfaces: ["adhoc"],
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
  last_used_at: null,
};

/** What the listing renders for a stored key the backend found damaged. */
const damagedKey: ApiKey = {
  id: DAMAGED_KEY_ID,
  name: "",
  prefix: "",
  surfaces: [],
  created_at: null,
  expires_at: null,
  revoked_at: null,
  last_used_at: null,
};

const createdKey: ApiKeyCreateResponse = {
  id: MCP_KEY_ID,
  name: MCP_KEY_NAME,
  prefix: MCP_PREFIX,
  surfaces: ["mcp"],
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
  last_used_at: null,
  token: PLAINTEXT_TOKEN,
};

let queryClient: QueryClient;

function Wrapper({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

function renderCard(
  keys: ApiKey[],
  truncated: ApiKeyListResponse["truncated"] = null,
) {
  listKeys.mockResolvedValue({ keys, truncated } satisfies ApiKeyListResponse);
  render(<ApiKeysCard />, { wrapper: Wrapper });
}

async function openCreateDialog() {
  renderCard([]);
  await screen.findByText(/No API keys yet/i);
  fireEvent.click(screen.getByRole("button", { name: /New key/i }));
}

async function mintKey() {
  await openCreateDialog();
  fireEvent.change(screen.getByLabelText("Name"), {
    target: { value: MCP_KEY_NAME },
  });
  fireEvent.click(screen.getByLabelText("MCP"));
  fireEvent.click(screen.getByRole("button", { name: /Create key/i }));
}

/** react-query keeps a settled mutation's result — the plaintext — until the observer resets. */
function mutationCacheHoldsToken(): boolean {
  return queryClient
    .getMutationCache()
    .getAll()
    .some(
      (mutation) =>
        (mutation.state.data as ApiKeyCreateResponse | undefined)?.token ===
        PLAINTEXT_TOKEN,
    );
}

describe("ApiKeysCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(NOW));
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        // gcTime 0 lets the cache drop a mutation as soon as reset() detaches its observer.
        mutations: { retry: false, gcTime: 0 },
      },
    });
    granted.current = [Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC];
    listKeys.mockResolvedValue({ keys: [], truncated: null });
    createKey.mockResolvedValue(createdKey);
    revokeKey.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("lists a key by name, prefix, surfaces and expiry", async () => {
    renderCard([mcpKey]);

    expect(await screen.findByText(MCP_KEY_NAME)).toBeInTheDocument();
    expect(screen.getByText(`${MCP_PREFIX}…`)).toBeInTheDocument();
    expect(screen.getByText("MCP")).toBeInTheDocument();
    expect(screen.getByText("expires in 3 months")).toBeInTheDocument();
  });

  it("shows the minted token exactly once and closes the create dialog", async () => {
    await mintKey();

    expect(await screen.findByText(PLAINTEXT_TOKEN)).toBeInTheDocument();
    expect(screen.getAllByText(PLAINTEXT_TOKEN)).toHaveLength(SHOWN_ONCE);
    expect(createKey).toHaveBeenCalledWith({
      name: MCP_KEY_NAME,
      surfaces: ["mcp"],
      expires_in_days: DEFAULT_EXPIRY_DAYS,
    });
    expect(screen.queryByLabelText("Name")).not.toBeInTheDocument();
  });

  it("drops the minted token from the mutation cache when the reveal is dismissed", async () => {
    await mintKey();
    await screen.findByText(PLAINTEXT_TOKEN);
    expect(mutationCacheHoldsToken()).toBe(true);

    fireEvent.click(
      screen.getByRole("button", { name: /I have stored the key/i }),
    );

    await waitFor(() =>
      expect(screen.queryByText(PLAINTEXT_TOKEN)).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(mutationCacheHoldsToken()).toBe(false));
  });

  it("refuses to mint until at least one surface is ticked", async () => {
    await openCreateDialog();
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: MCP_KEY_NAME },
    });

    expect(screen.getByRole("button", { name: /Create key/i })).toBeDisabled();

    fireEvent.click(screen.getByLabelText("Ad-hoc analysis"));

    expect(
      screen.getByRole("button", { name: /Create key/i }),
    ).not.toBeDisabled();
  });

  it("offers only the surfaces the user may mint", async () => {
    granted.current = [Permissions.ANALYZE_ADHOC];

    await openCreateDialog();

    expect(screen.getByLabelText("Ad-hoc analysis")).toBeInTheDocument();
    expect(screen.queryByLabelText("MCP")).not.toBeInTheDocument();
  });

  it("repeats the surface the server named when minting is refused", async () => {
    createKey.mockRejectedValue({
      response: { data: { detail: SURFACE_REFUSED } },
    });

    await mintKey();

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith(SURFACE_REFUSED),
    );
  });

  it("revokes only after the user confirms", async () => {
    const confirmed = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderCard([mcpKey]);
    await screen.findByText(MCP_KEY_NAME);

    fireEvent.click(screen.getByRole("button", { name: /Revoke key/i }));

    expect(confirmed).toHaveBeenCalledTimes(CALLED_ONCE);
    expect(revokeKey.mock.calls).toHaveLength(NOT_CALLED);

    confirmed.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: /Revoke key/i }));

    await waitFor(() => expect(revokeKey).toHaveBeenCalledWith(MCP_KEY_ID));
  });

  it("says how many keys the listing left out when its page saturated", async () => {
    renderCard([mcpKey], {
      limit: LIST_PAGE,
      returned: LIST_PAGE,
      total: TOTAL_KEYS,
    });

    expect(
      await screen.findByText(
        new RegExp(`Showing the newest ${LIST_PAGE} of ${TOTAL_KEYS} keys`),
      ),
    ).toBeInTheDocument();
  });

  it("reports an unstamped ad-hoc-only key as not recorded rather than unused", async () => {
    renderCard([adhocKey]);
    await screen.findByText(ADHOC_KEY_NAME);

    expect(screen.getByText("usage not recorded")).toBeInTheDocument();
    expect(screen.queryAllByText(/never/i)).toHaveLength(NONE);
  });

  it("shows when a stamped key was last used", async () => {
    renderCard([mcpKey]);
    await screen.findByText(MCP_KEY_NAME);

    expect(screen.getByText("last used 3 days ago")).toBeInTheDocument();
  });

  it("renders a damaged key and still offers to revoke it", async () => {
    const confirmed = vi.spyOn(window, "confirm").mockReturnValue(true);
    renderCard([damagedKey]);

    expect(await screen.findByText(/Unnamed key/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Revoke key/i }));

    expect(confirmed).toHaveBeenCalledTimes(CALLED_ONCE);
    await waitFor(() => expect(revokeKey).toHaveBeenCalledWith(DAMAGED_KEY_ID));
  });

  it("lists and offers to revoke keys for a user holding neither surface permission", async () => {
    granted.current = [];
    renderCard([mcpKey]);

    expect(await screen.findByText(MCP_KEY_NAME)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Revoke key/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /New key/i }),
    ).not.toBeInTheDocument();
  });
});
