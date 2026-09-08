import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

import type {
  AdhocApiKey,
  AdhocApiKeyCreateResponse,
  AdhocApiKeyListResponse,
} from "@/types/adhocKey";

import { AdhocApiKeysCard } from "../AdhocApiKeysCard";

const KEY_ID = "k1";
const KEY_NAME = "release pipeline";
const KEY_PREFIX = "dca_abcdefgh";
const PLAINTEXT_TOKEN = "dca_a-token-shown-exactly-once";
const DEFAULT_EXPIRY_DAYS = 90;
const CREATED_AT = "2026-09-01T10:00:00Z";
const EXPIRES_AT = "2026-12-01T10:00:00Z";
const NOT_CALLED = 0;
const LIST_PAGE = 100;
const TOTAL_KEYS = 103;
const CALLED_ONCE = 1;

const { createMutate, createReset, revokeMutate, listed } = vi.hoisted(() => ({
  createMutate: vi.fn(),
  createReset: vi.fn(),
  revokeMutate: vi.fn(),
  listed: { current: null as unknown },
}));

vi.mock("@/hooks/queries/use-adhoc-keys", () => {
  return {
    useAdhocKeys: () => ({ data: listed.current, isLoading: false }),
    useCreateAdhocKey: () => ({
      mutateAsync: createMutate,
      reset: createReset,
      isPending: false,
    }),
    useRevokeAdhocKey: () => ({ mutateAsync: revokeMutate, isPending: false }),
  };
});

const noKeys: AdhocApiKeyListResponse = { keys: [], truncated: null };

const storedKey: AdhocApiKey = {
  id: KEY_ID,
  name: KEY_NAME,
  prefix: KEY_PREFIX,
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
};

const createdKey: AdhocApiKeyCreateResponse = {
  id: KEY_ID,
  name: KEY_NAME,
  prefix: KEY_PREFIX,
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
  token: PLAINTEXT_TOKEN,
};

function openCreateDialog() {
  render(<AdhocApiKeysCard />);
  fireEvent.click(screen.getByRole("button", { name: /New key/i }));
}

async function revealToken() {
  openCreateDialog();
  fireEvent.change(screen.getByLabelText(/Name/i), {
    target: { value: KEY_NAME },
  });
  fireEvent.click(screen.getByRole("button", { name: /Create key/i }));
  expect(await screen.findByText(PLAINTEXT_TOKEN)).toBeInTheDocument();
}

async function expectTokenForgotten() {
  await waitFor(() =>
    expect(screen.queryByText(PLAINTEXT_TOKEN)).not.toBeInTheDocument(),
  );
  // The mutation result holds the plaintext too, and outlives the dialog without a reset.
  expect(createReset).toHaveBeenCalledTimes(CALLED_ONCE);
}

describe("AdhocApiKeysCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listed.current = noKeys;
    createMutate.mockResolvedValue(createdKey);
  });

  it("reveals the plaintext token once and drops it when the dialog is dismissed", async () => {
    await revealToken();
    expect(createMutate).toHaveBeenCalledWith({
      name: KEY_NAME,
      expires_in_days: DEFAULT_EXPIRY_DAYS,
    });

    fireEvent.click(
      screen.getByRole("button", { name: /I have stored the key/i }),
    );

    await expectTokenForgotten();
  });

  it("drops the token when the reveal dialog is dismissed with Escape", async () => {
    await revealToken();

    fireEvent.keyDown(document, { key: "Escape" });

    await expectTokenForgotten();
  });

  it("says how many keys the listing left out when its page saturated", () => {
    listed.current = {
      keys: [storedKey],
      truncated: { limit: LIST_PAGE, returned: LIST_PAGE, total: TOTAL_KEYS },
    } satisfies AdhocApiKeyListResponse;

    render(<AdhocApiKeysCard />);

    expect(
      screen.getByText(
        new RegExp(`Showing the newest ${LIST_PAGE} of ${TOTAL_KEYS} keys`),
      ),
    ).toBeInTheDocument();
  });

  it("says nothing about truncation when the whole list came back", () => {
    listed.current = { keys: [storedKey], truncated: null };

    render(<AdhocApiKeysCard />);

    expect(screen.queryByText(/Showing the newest/)).not.toBeInTheDocument();
  });

  it("refuses to mint a nameless key", () => {
    openCreateDialog();

    fireEvent.click(screen.getByRole("button", { name: /Create key/i }));

    expect(createMutate.mock.calls).toHaveLength(NOT_CALLED);
  });
});
