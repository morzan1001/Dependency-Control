import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, it, expect, vi } from "vitest";

import { toast } from "sonner";

import { webhookApi } from "@/api/webhooks";
import type { Webhook } from "@/types/webhook";

import { WebhookManager } from "../WebhookManager";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/api/webhooks", () => ({ webhookApi: { test: vi.fn() } }));

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    permissions: ["webhook:create", "webhook:delete", "webhook:update"],
    hasPermission: (p: string) =>
      ["webhook:create", "webhook:delete", "webhook:update"].includes(p),
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

describe("WebhookManager", () => {
  it("exposes every webhook event type in the create dialog", () => {
    render(
      <WebhookManager
        webhooks={[]}
        isLoading={false}
        onCreate={vi.fn().mockResolvedValue({ id: "w1" })}
        onUpdate={vi.fn()}
        onDelete={vi.fn().mockResolvedValue(undefined)}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));

    expect(screen.getByLabelText(/Scan completed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Vulnerability found/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Analysis failed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/SBOM ingested/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Crypto asset ingested/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Crypto policy changed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/License policy changed/i)).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Compliance report generated/i),
    ).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Events" })).getAllByRole("checkbox")).toHaveLength(8);
  });

  it.each([
    [false, undefined],
    [true, "generic"],
  ])("sends webhook_type generic for a workflow URL only when the JSON opt-out is ticked (%s)", async (optOut, expected) => {
    const onCreate = vi.fn().mockResolvedValue({ id: "w1" });
    render(
      <WebhookManager webhooks={[]} isLoading={false} onCreate={onCreate} onUpdate={vi.fn()} onDelete={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));
    fireEvent.change(screen.getByLabelText("URL"), {
      target: { value: "https://prod-1.westeurope.logic.azure.com/workflows/abc/triggers/manual" },
    });
    if (optOut) fireEvent.click(screen.getByLabelText(/event JSON instead/i));
    fireEvent.click(screen.getByLabelText(/Scan completed/i));
    fireEvent.click(screen.getByRole("button", { name: /Create Webhook/i }));

    await waitFor(() => expect(onCreate).toHaveBeenCalledTimes(1));
    expect(onCreate.mock.calls[0][0].webhook_type).toBe(expected);
  });

  it("keeps a create draft across closing and reopening the dialog", () => {
    render(<WebhookManager webhooks={[]} isLoading={false} onCreate={vi.fn()} onUpdate={vi.fn()} onDelete={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));
    fireEvent.change(screen.getByLabelText("URL"), {
      target: { value: "https://example.com/draft" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));

    expect(screen.getByLabelText("URL")).toHaveValue("https://example.com/draft");
  });

  const slackHook: Webhook = {
    id: "w-slack",
    url: "https://hooks.slack.com/services/T0/B0/x",
    events: ["vulnerability.found"],
    is_active: true,
    created_at: "2026-10-07T07:26:42Z",
    webhook_type: "slack",
    last_failure_at: "2026-10-07T09:25:42Z",
  };

  const renderWith = (webhooks: Webhook[]) =>
    render(
      <WebhookManager
        webhooks={webhooks}
        isLoading={false}
        onCreate={vi.fn()}
        onUpdate={vi.fn()}
        onDelete={vi.fn().mockResolvedValue(undefined)}
      />,
    );

  it("labels a Slack webhook as Slack", () => {
    renderWith([slackHook]);

    expect(screen.getByText("Slack")).toBeInTheDocument();
  });

  it("marks a webhook whose last delivery failed", () => {
    renderWith([slackHook, { ...slackHook, id: "w-ok", last_triggered_at: "2026-10-07T10:00:00Z" }]);

    expect(screen.getAllByText("Failing")).toHaveLength(1);
  });

  it("shows a paused webhook as Paused, not by its last delivery", () => {
    renderWith([{ ...slackHook, is_active: false }]);

    expect(screen.getByText("Paused")).toBeInTheDocument();
    expect(screen.queryByText("Failing")).not.toBeInTheDocument();
  });

  it("shows why a test delivery failed", async () => {
    vi.mocked(webhookApi.test).mockResolvedValue({ success: false, status_code: 400, error: "HTTP 400: no_text" });
    renderWith([slackHook]);

    fireEvent.click(screen.getByRole("button", { name: /Send test/i }));

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("HTTP 400: no_text")));
    expect(webhookApi.test).toHaveBeenCalledWith("w-slack");
  });

  it("deletes a webhook from its named Delete button", async () => {
    const onDelete = vi.fn().mockResolvedValue(undefined);
    render(<WebhookManager webhooks={[slackHook]} isLoading={false} onCreate={vi.fn()} onUpdate={vi.fn()} onDelete={onDelete} />);

    fireEvent.click(screen.getByRole("button", { name: "Delete webhook" }));

    await waitFor(() => expect(onDelete).toHaveBeenCalledWith("w-slack"));
  });

  it("stores a Slack URL with its detected type after a Teams URL was edited away", async () => {
    const onCreate = vi.fn().mockResolvedValue({ id: "w-new" });
    render(<WebhookManager webhooks={[]} isLoading={false} onCreate={onCreate} onUpdate={vi.fn()} onDelete={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));
    const url = screen.getByLabelText("URL");

    fireEvent.change(url, { target: { value: "https://contoso.webhook.office.com/webhookb2/abc" } });
    fireEvent.click(screen.getByLabelText(/send the event JSON instead/i));
    fireEvent.change(url, { target: { value: "https://hooks.slack.com/services/T0/B0/x" } });
    fireEvent.click(screen.getByLabelText(/Vulnerability found/i));
    fireEvent.click(screen.getByRole("button", { name: /Create Webhook/i }));

    await waitFor(() => expect(onCreate).toHaveBeenCalled());
    expect(onCreate.mock.calls[0][0]).not.toHaveProperty("webhook_type");
  });
  it("shows the API error when creating a webhook fails", async () => {
    const onCreate = vi.fn().mockRejectedValue({ response: { data: { detail: "Plain HTTP is only allowed for loopback hosts" } } });
    render(<WebhookManager webhooks={[]} isLoading={false} onCreate={onCreate} onUpdate={vi.fn()} onDelete={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));
    fireEvent.change(screen.getByLabelText("URL"), { target: { value: "http://example.com/hook" } });
    fireEvent.click(screen.getByLabelText(/Scan completed/i));
    fireEvent.click(screen.getByRole("button", { name: /Create Webhook/i }));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("Failed to create webhook", {
        description: "Plain HTTP is only allowed for loopback hosts",
      }),
    );
  });

  describe("editing a webhook", () => {
    const TEAMS_URL = "https://contoso.webhook.office.com/webhookb2/abc";
    const SLACK_URL = "https://hooks.slack.com/services/T0/B0/x";

    const stored: Webhook = {
      id: "w-edit",
      url: "https://example.com/hook",
      events: ["scan.completed", "analysis.failed"],
      is_active: true,
      created_at: "2026-10-01T08:00:00Z",
      webhook_type: "generic",
    };
    const teamsCards: Webhook = { ...stored, url: TEAMS_URL, webhook_type: "teams" };
    const teamsJson: Webhook = { ...stored, url: TEAMS_URL, webhook_type: "generic" };
    const apiTeams: Webhook = { ...stored, webhook_type: "teams" };

    beforeEach(() => vi.clearAllMocks());

    const renderEditor = (webhook: Webhook, onUpdate = vi.fn().mockResolvedValue(webhook)) => {
      render(
        <WebhookManager webhooks={[webhook]} isLoading={false} onCreate={vi.fn()} onUpdate={onUpdate} onDelete={vi.fn()} />,
      );
      fireEvent.click(screen.getByRole("button", { name: "Edit webhook" }));
      return onUpdate;
    };
    const urlInput = () => screen.getByLabelText("URL");
    const optOut = () => screen.queryByLabelText(/send the event JSON instead/i);
    const saveButton = () => screen.getByRole("button", { name: "Save changes" });

    const saved = async (onUpdate: ReturnType<typeof vi.fn>) => {
      fireEvent.click(saveButton());
      await waitFor(() => expect(onUpdate).toHaveBeenCalledTimes(1));
      return onUpdate.mock.calls[0];
    };

    it("opens prefilled with the webhook and offers Save only after a change", () => {
      renderEditor(stored);

      expect(urlInput()).toHaveValue("https://example.com/hook");
      expect(screen.getByLabelText(/Scan completed/i)).toBeChecked();
      expect(screen.getByLabelText(/Analysis failed/i)).toBeChecked();
      expect(screen.getByLabelText(/Vulnerability found/i)).not.toBeChecked();
      expect(screen.getByLabelText(/^Secret/)).toHaveValue("");
      expect(screen.getByRole("switch", { name: "Active" })).toBeChecked();
      expect(saveButton()).toBeDisabled();
    });

    it.each([
      ["closed", () => fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" })],
      [
        "saved",
        () => {
          fireEvent.click(screen.getByRole("switch", { name: "Active" }));
          fireEvent.click(saveButton());
        },
      ],
    ])("returns focus to the Edit button once the dialog is %s", async (_case, close) => {
      renderEditor(stored);

      close();

      await waitFor(() => expect(screen.getByRole("button", { name: "Edit webhook" })).toHaveFocus());
    });

    it("diffs against the webhook as it was when the dialog opened", async () => {
      const onUpdate = vi.fn().mockResolvedValue(stored);
      const props = { isLoading: false, onCreate: vi.fn(), onUpdate, onDelete: vi.fn() };
      const { rerender } = render(<WebhookManager webhooks={[stored]} {...props} />);
      fireEvent.click(screen.getByRole("button", { name: "Edit webhook" }));

      rerender(<WebhookManager webhooks={[{ ...stored, events: ["scan.completed"] }]} {...props} />);
      fireEvent.change(urlInput(), { target: { value: "https://example.com/fixed" } });
      const [, data] = await saved(onUpdate);

      expect(data).toStrictEqual({ url: "https://example.com/fixed" });
    });

    it("discards unsaved edits when the dialog is closed", () => {
      renderEditor(stored);
      fireEvent.change(urlInput(), { target: { value: "https://example.com/abandoned" } });

      fireEvent.click(screen.getByRole("button", { name: "Close" }));
      fireEvent.click(screen.getByRole("button", { name: "Edit webhook" }));

      expect(urlInput()).toHaveValue("https://example.com/hook");
    });

    it("treats an event unticked and ticked again as unchanged", () => {
      renderEditor(stored);

      fireEvent.click(screen.getByLabelText(/Scan completed/i));
      fireEvent.click(screen.getByLabelText(/Scan completed/i));

      expect(saveButton()).toBeDisabled();
    });

    it.each([
      ["the new URL", () => fireEvent.change(urlInput(), { target: { value: "https://example.com/fixed" } }), { url: "https://example.com/fixed" }],
      [
        "the new event list",
        () => fireEvent.click(screen.getByLabelText(/Vulnerability found/i)),
        { events: ["scan.completed", "analysis.failed", "vulnerability.found"] },
      ],
      ["a newly entered secret", () => fireEvent.change(screen.getByLabelText(/^Secret/), { target: { value: "rotated" } }), { secret: "rotated" }],
      ["a null secret to remove the stored one", () => fireEvent.click(screen.getByLabelText(/Remove the stored secret/i)), { secret: null }],
      ["is_active false to pause it", () => fireEvent.click(screen.getByRole("switch", { name: "Active" })), { is_active: false }],
    ])("sends only %s", async (_change, edit, expected) => {
      const onUpdate = renderEditor(stored);

      edit();
      const [id, data] = await saved(onUpdate);

      expect(id).toBe("w-edit");
      expect(data).toStrictEqual(expected);
    });

    it("removes the stored secret even when a new one was typed first", async () => {
      const onUpdate = renderEditor(stored);

      fireEvent.change(screen.getByLabelText(/^Secret/), { target: { value: "rotated" } });
      fireEvent.click(screen.getByLabelText(/Remove the stored secret/i));
      expect(screen.getByLabelText(/^Secret/)).toBeDisabled();
      const [, data] = await saved(onUpdate);

      expect(data).toStrictEqual({ secret: null });
    });

    it("offers the JSON opt-out only while the URL is a Teams URL", () => {
      renderEditor(stored);
      expect(optOut()).not.toBeInTheDocument();

      fireEvent.change(urlInput(), { target: { value: TEAMS_URL } });

      expect(optOut()).toBeInTheDocument();
    });

    it("shows the stored JSON opt-out of a Teams webhook ticked", () => {
      renderEditor(teamsJson);

      expect(optOut()).toBeChecked();
    });

    it.each([
      ["ticking the opt-out sends the generic type", teamsCards, () => fireEvent.click(optOut()!), { webhook_type: "generic" }],
      ["unticking the opt-out sends the Teams type", teamsJson, () => fireEvent.click(optOut()!), { webhook_type: "teams" }],
      [
        "a new Teams URL keeps a ticked opt-out",
        teamsJson,
        () => fireEvent.change(urlInput(), { target: { value: "https://contoso.webhook.office.com/webhookb2/def" } }),
        { url: "https://contoso.webhook.office.com/webhookb2/def", webhook_type: "generic" },
      ],
      [
        "a Slack URL leaves the type to the server",
        teamsJson,
        () => fireEvent.change(urlInput(), { target: { value: SLACK_URL } }),
        { url: SLACK_URL },
      ],
      [
        "a plain URL leaves the opt-out to the server",
        teamsJson,
        () => fireEvent.change(urlInput(), { target: { value: "https://example.com/fixed" } }),
        { url: "https://example.com/fixed" },
      ],
      [
        "a new URL keeps a type set over the API",
        apiTeams,
        () => fireEvent.change(urlInput(), { target: { value: "https://example.com/fixed" } }),
        { url: "https://example.com/fixed", webhook_type: "teams" },
      ],
      [
        "a new Teams URL leaves a type set over the API to the server",
        apiTeams,
        () => fireEvent.change(urlInput(), { target: { value: TEAMS_URL } }),
        { url: TEAMS_URL },
      ],
    ])("%s", async (_case, webhook, edit, expected) => {
      const onUpdate = renderEditor(webhook);

      edit();
      const [, data] = await saved(onUpdate);

      expect(data).toStrictEqual(expected);
    });

    it("closes once the change is saved", async () => {
      const onUpdate = renderEditor(stored);

      fireEvent.click(screen.getByRole("switch", { name: "Active" }));
      await saved(onUpdate);

      await waitFor(() => expect(screen.queryByRole("button", { name: "Save changes" })).not.toBeInTheDocument());
      expect(toast.success).toHaveBeenCalledWith("Webhook updated");
    });

    it("shows the API error and stays open when saving fails", async () => {
      const onUpdate = renderEditor(
        stored,
        vi.fn().mockRejectedValue({ response: { data: { detail: "Plain HTTP is only allowed for loopback hosts" } } }),
      );

      fireEvent.change(urlInput(), { target: { value: "http://example.com/hook" } });
      await saved(onUpdate);

      await waitFor(() =>
        expect(toast.error).toHaveBeenCalledWith("Failed to update webhook", {
          description: "Plain HTTP is only allowed for loopback hosts",
        }),
      );
      expect(saveButton()).toBeInTheDocument();
    });

    it.each([
      ["a false update permission", false],
      ["an update permission the user lacks", "system:manage"],
    ])("offers no Edit for %s", (_case, updatePermission) => {
      render(
        <WebhookManager
          webhooks={[stored]}
          isLoading={false}
          onCreate={vi.fn()}
          onUpdate={vi.fn()}
          onDelete={vi.fn()}
          updatePermission={updatePermission}
        />,
      );

      expect(screen.queryByRole("button", { name: "Edit webhook" })).not.toBeInTheDocument();
    });
  });
});
