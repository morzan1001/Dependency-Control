import { useState } from "react"
import { Webhook, WebhookCreate, WebhookType, WebhookUpdate } from "@/types/webhook"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { Switch } from "@/components/ui/switch"
import { SecretInput } from "@/components/settings/SecretInput"
import { toast } from "sonner"
import { getErrorMessage } from "@/lib/utils"

// Mirrors the server's detection, which decides the type when the request names none.
function detectWebhookType(url: string): WebhookType {
  let host: string;
  let path: string;
  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase();
    path = parsed.pathname;
  } catch {
    return "generic";
  }
  if (host === "hooks.slack.com" && path.startsWith("/services/")) return "slack";
  if (host === "webhook.office.com" || host.endsWith(".webhook.office.com")) return "teams";
  if ((host === "logic.azure.com" || host.endsWith(".logic.azure.com")) && path.includes("/workflows/")) return "teams";
  if ((host === "api.powerplatform.com" || host.endsWith(".api.powerplatform.com")) && path.includes("/workflows/")) return "teams";
  return "generic";
}

const AVAILABLE_EVENTS = [
  {
    id: "scan.completed",
    label: "Scan completed",
    description: "Fires when a project scan finishes successfully.",
  },
  {
    id: "vulnerability.found",
    label: "Vulnerability found",
    description: "Fires when a scan finds critical, high, KEV or high-EPSS vulnerabilities.",
  },
  {
    id: "analysis.failed",
    label: "Analysis failed",
    description: "Fires when a scan or analysis run fails.",
  },
  {
    id: "sbom.ingested",
    label: "SBOM ingested",
    description: "Fires when an SBOM is ingested for a project.",
  },
  {
    id: "crypto_asset.ingested",
    label: "Crypto asset ingested",
    description: "Fires when crypto assets (CBOM) are imported or updated.",
  },
  {
    id: "crypto_policy.changed",
    label: "Crypto policy changed",
    description: "Fires on every create/update/delete/revert of a crypto policy.",
  },
  {
    id: "license_policy.changed",
    label: "License policy changed",
    description: "Fires on every create/update/delete/revert of a license policy.",
  },
  {
    id: "compliance_report.generated",
    label: "Compliance report generated",
    description: "Fires when a compliance report finishes, completed or failed.",
  },
]

interface WebhookFormState {
  url: string
  events: string[]
  secret: string | null
  sendJson: boolean
  isActive: boolean
}

const EMPTY_FORM: WebhookFormState = {
  url: "",
  events: [],
  secret: "",
  sendJson: false,
  isActive: true,
}

function sendsJsonToTeams(webhook: Webhook): boolean {
  return detectWebhookType(webhook.url) === "teams" && webhook.webhook_type === "generic"
}

function formFor(webhook: Webhook): WebhookFormState {
  return {
    ...EMPTY_FORM,
    url: webhook.url,
    events: webhook.events,
    sendJson: sendsJsonToTeams(webhook),
    isActive: webhook.is_active,
  }
}

function createPayload(form: WebhookFormState): WebhookCreate {
  return {
    url: form.url,
    events: form.events,
    ...(form.secret ? { secret: form.secret } : {}),
    // The JSON opt-out exists for Teams URLs only; a value left from an edited-away Teams URL must not stick.
    ...(form.sendJson && detectWebhookType(form.url) === "teams" ? { webhook_type: "generic" as const } : {}),
  }
}

function changedFields(webhook: Webhook, form: WebhookFormState): WebhookUpdate {
  const changes: WebhookUpdate = {}
  const urlChanged = form.url !== webhook.url
  if (urlChanged) changes.url = form.url
  if (form.events.length !== webhook.events.length || form.events.some(e => !webhook.events.includes(e))) {
    changes.events = form.events
  }
  if (form.secret !== "") changes.secret = form.secret
  if (form.isActive !== webhook.is_active) changes.is_active = form.isActive
  // The server detects the type of a new URL sent without one, so only the Teams opt-out and a type set over the API need naming.
  const mustNameType = urlChanged ? form.sendJson : form.sendJson !== sendsJsonToTeams(webhook)
  const newType = detectWebhookType(form.url)
  const storedType = webhook.webhook_type ?? "generic"
  const typeSetOverApi = storedType !== "generic" && storedType !== detectWebhookType(webhook.url)
  if (mustNameType && newType === "teams") {
    changes.webhook_type = form.sendJson ? "generic" : "teams"
  } else if (urlChanged && typeSetOverApi && newType === "generic") {
    changes.webhook_type = storedType
  }
  return changes
}

type WebhookFormProps = { readonly onSaved: () => void } & (
  | { readonly webhook?: undefined; readonly onCreate: (data: WebhookCreate) => Promise<unknown> }
  | { readonly webhook: Webhook; readonly onUpdate: (data: WebhookUpdate) => Promise<unknown> }
)

// Owns the DialogContent rather than living inside it, so a create draft survives closing the dialog.
export function WebhookForm(props: WebhookFormProps) {
  const { webhook, onSaved } = props
  const [form, setForm] = useState<WebhookFormState>(() => (webhook ? formFor(webhook) : EMPTY_FORM))
  const patchForm = (patch: Partial<WebhookFormState>) => setForm(prev => ({ ...prev, ...patch }))
  const isTeamsUrl = detectWebhookType(form.url) === "teams"
  const unchanged = webhook !== undefined && Object.keys(changedFields(webhook, form)).length === 0

  const handleSubmit = async () => {
    try {
      if (props.webhook) {
        await props.onUpdate(changedFields(props.webhook, form))
        toast.success("Webhook updated")
      } else {
        await props.onCreate(createPayload(form))
        setForm(EMPTY_FORM)
        toast.success("Webhook created")
      }
      onSaved()
    } catch (error) {
      toast.error(webhook ? "Failed to update webhook" : "Failed to create webhook", {
        description: getErrorMessage(error),
      })
    }
  }

  const toggleEvent = (eventId: string) => {
    setForm(prev => {
      const events = prev.events.includes(eventId)
        ? prev.events.filter(e => e !== eventId)
        : [...prev.events, eventId]
      return { ...prev, events }
    })
  }

  return (
    <DialogContent>
      <DialogHeader>
        <DialogTitle>{webhook ? "Edit Webhook" : "Add Webhook"}</DialogTitle>
      </DialogHeader>
      <div className="space-y-4 py-4">
        {webhook && (
          <div className="flex items-center justify-between">
            <div className="grid gap-0.5 leading-tight">
              <Label htmlFor="webhook-active">Active</Label>
              <span className="text-xs text-muted-foreground">A paused webhook receives no deliveries.</span>
            </div>
            <Switch id="webhook-active" checked={form.isActive} onCheckedChange={isActive => patchForm({ isActive })} />
          </div>
        )}
        <div className="space-y-2">
          <Label htmlFor="webhook-url">URL</Label>
          <Input
            id="webhook-url"
            value={form.url}
            onChange={e => patchForm({ url: e.target.value })}
            placeholder="https://example.com/webhook"
          />
          {isTeamsUrl && (
            <div className="flex items-start space-x-2">
              <Checkbox
                id="webhook-send-json"
                checked={form.sendJson}
                onCheckedChange={sendJson => patchForm({ sendJson })}
                className="mt-0.5"
              />
              <Label htmlFor="webhook-send-json" className="text-xs font-normal text-muted-foreground">
                Detected as a Microsoft Teams workflow URL, so payloads are sent as Adaptive Cards. Tick to
                send the event JSON instead, e.g. for a plain Logic App or Power Automate flow.
              </Label>
            </div>
          )}
        </div>
        <div className="space-y-2">
          <Label htmlFor="webhook-secret">Secret (Optional)</Label>
          <SecretInput
            id="webhook-secret"
            value={form.secret}
            configured={webhook?.secret_configured ?? false}
            onChange={secret => patchForm({ secret })}
          />
        </div>
        <div className="space-y-2">
          <Label id="webhook-events-label">Events</Label>
          <div role="group" aria-labelledby="webhook-events-label" className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {AVAILABLE_EVENTS.map(event => (
              <div key={event.id} className="flex items-start space-x-2">
                <Checkbox
                  id={event.id}
                  checked={form.events.includes(event.id)}
                  onCheckedChange={() => toggleEvent(event.id)}
                  className="mt-1"
                />
                <div className="grid gap-0.5 leading-tight">
                  <Label htmlFor={event.id} className="font-medium">
                    {event.label}
                  </Label>
                  <span className="text-xs text-muted-foreground">
                    {event.description}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
        <Button onClick={handleSubmit} className="w-full" disabled={!form.url || form.events.length === 0 || unchanged}>
          {webhook ? "Save changes" : "Create Webhook"}
        </Button>
      </div>
    </DialogContent>
  )
}
