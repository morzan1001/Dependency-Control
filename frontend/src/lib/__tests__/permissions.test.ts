import { describe, it, expect } from "vitest";

import {
  ALL_PERMISSIONS,
  PERMISSION_GROUPS,
  PRESET_USER,
  PRESET_VIEWER,
  Permissions,
} from "@/lib/permissions";

describe("ANALYZE_ADHOC permission", () => {
  it("uses the same string as the backend", () => {
    expect(Permissions.ANALYZE_ADHOC).toBe("analyze:adhoc");
  });

  it("is grantable from the admin permission editor", () => {
    expect(ALL_PERMISSIONS).toContain(Permissions.ANALYZE_ADHOC);
    const rendered = PERMISSION_GROUPS.flatMap((g) => g.permissions).map((p) => p.id);
    expect(rendered).toContain(Permissions.ANALYZE_ADHOC);
  });

  it("stays out of the non-admin presets", () => {
    expect(PRESET_USER).not.toContain(Permissions.ANALYZE_ADHOC);
    expect(PRESET_VIEWER).not.toContain(Permissions.ANALYZE_ADHOC);
  });
});
