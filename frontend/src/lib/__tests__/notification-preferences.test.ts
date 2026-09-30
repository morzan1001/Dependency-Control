import { describe, it, expect } from "vitest";
import { memberPreferences, enforcedPreferences } from "../notification-preferences";
import type { Project } from "@/types/project";

const ADMIN_PREFS = { vulnerability_found: ["email"] };
const MEMBER_PREFS = { analysis_completed: ["slack"] };

function project(members: Project["members"]): Project {
  return { id: "p", name: "p", members } as Project;
}

describe("memberPreferences", () => {
  it("reads an admin's own overrides", () => {
    // The settings form used to branch on role here and read a field the backend never sends,
    // so an admin's saved project preferences never loaded.
    const p = project([{ user_id: "u1", role: "admin", notification_preferences: ADMIN_PREFS }]);

    expect(memberPreferences(p, "u1")).toEqual(ADMIN_PREFS);
  });

  it("reads a non-admin's own overrides", () => {
    const p = project([{ user_id: "u2", role: "viewer", notification_preferences: MEMBER_PREFS }]);

    expect(memberPreferences(p, "u2")).toEqual(MEMBER_PREFS);
  });

  it("treats an empty map as no override so the caller can fall back to the global preferences", () => {
    const p = project([{ user_id: "u1", role: "admin", notification_preferences: {} }]);

    expect(memberPreferences(p, "u1")).toBeUndefined();
  });

  it("returns nothing for a user who is not a member", () => {
    expect(memberPreferences(project([]), "nobody")).toBeUndefined();
  });
});

describe("enforcedPreferences", () => {
  it("shows what the enforcing admin saved, not any admin member's own preferences", () => {
    const p = {
      ...project([{ user_id: "u1", role: "admin", notification_preferences: ADMIN_PREFS }]),
      enforce_notification_settings: true,
      enforced_notification_preferences: MEMBER_PREFS,
    };

    expect(enforcedPreferences(p)).toEqual(MEMBER_PREFS);
  });

  it("keeps an enforced mute, so the form shows every event off", () => {
    const muted = { analysis_completed: [], vulnerability_found: [] };

    expect(enforcedPreferences({ ...project([]), enforced_notification_preferences: muted })).toEqual(muted);
  });

  it("returns nothing while no enforced preferences were saved", () => {
    const p = project([{ user_id: "u1", role: "admin", notification_preferences: ADMIN_PREFS }]);

    expect(enforcedPreferences(p)).toBeUndefined();
  });
});
