import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

import type {
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

const { createMutate, revokeMutate } = vi.hoisted(() => ({
  createMutate: vi.fn(),
  revokeMutate: vi.fn(),
}));

vi.mock("@/hooks/queries/use-adhoc-keys", () => {
  const noKeys: AdhocApiKeyListResponse = { keys: [] };
  return {
    useAdhocKeys: () => ({ data: noKeys, isLoading: false }),
    useCreateAdhocKey: () => ({ mutateAsync: createMutate, isPending: false }),
    useRevokeAdhocKey: () => ({ mutateAsync: revokeMutate, isPending: false }),
  };
});

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

describe("AdhocApiKeysCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createMutate.mockResolvedValue(createdKey);
  });

  it("reveals the plaintext token once and drops it when the dialog is dismissed", async () => {
    openCreateDialog();
    fireEvent.change(screen.getByLabelText(/Name/i), {
      target: { value: KEY_NAME },
    });
    fireEvent.click(screen.getByRole("button", { name: /Create key/i }));

    expect(await screen.findByText(PLAINTEXT_TOKEN)).toBeInTheDocument();
    expect(createMutate).toHaveBeenCalledWith({
      name: KEY_NAME,
      expires_in_days: DEFAULT_EXPIRY_DAYS,
    });

    fireEvent.click(
      screen.getByRole("button", { name: /I have stored the key/i }),
    );

    await waitFor(() =>
      expect(screen.queryByText(PLAINTEXT_TOKEN)).not.toBeInTheDocument(),
    );
  });

  it("refuses to mint a nameless key", () => {
    openCreateDialog();

    fireEvent.click(screen.getByRole("button", { name: /Create key/i }));

    expect(createMutate.mock.calls).toHaveLength(NOT_CALLED);
  });
});
