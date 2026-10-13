import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { userApi } from "@/api/users";
import type { User } from "@/types/user";
import { useUpdateUser, userKeys } from "../use-users";

vi.mock("@/api/users", () => ({ userApi: { update: vi.fn() } }));

const ADMIN: User = {
  id: "u-admin",
  username: "admin",
  email: "admin@corp.com",
  is_active: true,
  permissions: ["user:update"],
  totp_enabled: false,
};

describe("useUpdateUser", () => {
  it("refreshes the signed-in account, which an administrator may just have renamed", async () => {
    const client = new QueryClient();
    client.setQueryData(userKeys.me, ADMIN);
    vi.mocked(userApi.update).mockResolvedValue({ ...ADMIN, username: "root" });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useUpdateUser(), { wrapper });

    await result.current.mutateAsync({ id: ADMIN.id, data: { username: "root" } });

    expect(client.getQueryState(userKeys.me)?.isInvalidated).toBe(true);
  });
});
