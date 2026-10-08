import { useState } from "react"
import { WebhookCreate, WebhookType } from "@/types/webhook"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { toast } from "sonner"

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
  secret: string
  sendJson: boolean
}

const EMPTY_FORM: WebhookFormState = { url: "", events: [], secret: "", sendJson: false }

interface WebhookFormProps {
  readonly onCreate: (data: WebhookCreate) => Promise<unknown>
  readonly onSaved: () => void
}

// Owns the DialogContent rather than living inside it, so a create draft survives closing the dialog.
export function WebhookForm({ onCreate, onSaved }: WebhookFormProps) {
  const [form, setForm] = useState<WebhookFormState>(EMPTY_FORM)
  const isTeamsUrl = detectWebhookType(form.url) === "teams"

  const handleSubmit = async () => {
    try {
      await onCreate({
        url: form.url,
        events: form.events,
        ...(form.secret ? { secret: form.secret } : {}),
        // The JSON opt-out exists for Teams URLs only; a value left from an edited-away Teams URL must not stick.
        ...(form.sendJson && isTeamsUrl ? { webhook_type: "generic" as const } : {}),
      })
      onSaved()
      setForm(EMPTY_FORM)
      toast.success("Webhook created")
    } catch {
      toast.error("Failed to create webhook")
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
        <DialogTitle>Add Webhook</DialogTitle>
      </DialogHeader>
      <div className="space-y-4 py-4">
        <div className="space-y-2">
          <Label>URL</Label>
          <Input
            value={form.url}
            onChange={e => setForm(prev => ({ ...prev, url: e.target.value }))}
            placeholder="https://example.com/webhook"
          />
          {isTeamsUrl && (
            <div className="flex items-start space-x-2">
              <Checkbox
                id="webhook-send-json"
                checked={form.sendJson}
                onCheckedChange={checked => setForm(prev => ({ ...prev, sendJson: checked }))}
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
          <Label>Secret (Optional)</Label>
          <Input
            value={form.secret}
            onChange={e => setForm(prev => ({ ...prev, secret: e.target.value }))}
            type="password"
          />
        </div>
        <div className="space-y-2">
          <Label>Events</Label>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
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
        <Button onClick={handleSubmit} className="w-full" disabled={!form.url || form.events.length === 0}>Create Webhook</Button>
      </div>
    </DialogContent>
  )
}
