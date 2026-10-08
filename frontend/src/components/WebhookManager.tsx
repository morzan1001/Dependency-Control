import { useState } from "react"
import { Webhook, WebhookCreate, WebhookType } from "@/types/webhook"
import { webhookApi } from "@/api/webhooks"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"
import { Trash2, Plus, Send } from "lucide-react"
import { toast } from "sonner"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuth } from "@/context/useAuth"
import { useDialogState } from "@/hooks/use-dialog-state"
import { formatDate, formatDateTime, getErrorMessage } from "@/lib/utils"

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

const TYPE_LABELS: Record<WebhookType, string> = { generic: "Generic", teams: "Teams", slack: "Slack" };

// The server stamps last_triggered_at on success and last_failure_at on failure, so the later one is the current state.
function isFailing(webhook: Webhook): boolean {
  if (!webhook.last_failure_at) return false;
  return !webhook.last_triggered_at || Date.parse(webhook.last_failure_at) > Date.parse(webhook.last_triggered_at);
}

interface WebhookManagerProps {
  readonly webhooks: Webhook[]
  readonly isLoading: boolean
  readonly onCreate: (data: WebhookCreate) => Promise<Webhook>
  readonly onDelete: (id: string) => Promise<void>
  readonly title?: string
  readonly description?: string
  readonly createPermission?: string | boolean
  readonly deletePermission?: string | boolean
  readonly testPermission?: string | boolean
}

export function WebhookManager({ 
  webhooks, 
  isLoading, 
  onCreate, 
  onDelete, 
  title = "Webhooks", 
  description = "Manage webhooks for event notifications.",
  createPermission = "webhook:create",
  deletePermission = "webhook:delete",
  testPermission = "webhook:update"
}: WebhookManagerProps) {
  const createDialog = useDialogState()
  const { hasPermission } = useAuth()
  const canCreate = typeof createPermission === 'boolean'
    ? createPermission
    : hasPermission(createPermission)
  const canDeleteWh = typeof deletePermission === 'boolean'
    ? deletePermission
    : hasPermission(deletePermission)
  const canTest = typeof testPermission === 'boolean'
    ? testPermission
    : hasPermission(testPermission)
  const [newWebhook, setNewWebhook] = useState<WebhookCreate>({
    url: "",
    events: [],
    secret: ""
  })

  const availableEvents = [
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

  const handleCreate = async () => {
    if (!newWebhook.url || newWebhook.events.length === 0) return
    try {
      const payload: WebhookCreate = {
        url: newWebhook.url,
        events: newWebhook.events,
        ...(newWebhook.secret ? { secret: newWebhook.secret } : {}),
        // The JSON opt-out exists for Teams URLs only; a value left from an edited-away Teams URL must not stick.
        ...(newWebhook.webhook_type && detectWebhookType(newWebhook.url) === "teams" ? { webhook_type: newWebhook.webhook_type } : {}),
      }
      await onCreate(payload)
      createDialog.closeDialog()
      setNewWebhook({ url: "", events: [], secret: "" })
      toast.success("Webhook created")
    } catch {
      toast.error("Failed to create webhook")
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await onDelete(id)
      toast.success("Webhook deleted")
    } catch {
      toast.error("Failed to delete webhook")
    }
  }

  const handleTest = async (id: string) => {
    try {
      const result = await webhookApi.test(id)
      if (result.success) toast.success(`Test delivered (HTTP ${result.status_code})`)
      else toast.error(`Test failed: ${result.error}`)
    } catch (error) {
      toast.error(getErrorMessage(error))
    }
  }

  const toggleEvent = (eventId: string) => {
    setNewWebhook(prev => {
      const events = prev.events.includes(eventId)
        ? prev.events.filter(e => e !== eventId)
        : [...prev.events, eventId]
      return { ...prev, events }
    })
  }

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-32 mb-2" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
        {canCreate && (
          <Dialog open={createDialog.open} onOpenChange={createDialog.setOpen}>
            <DialogTrigger asChild>
              <Button size="sm"><Plus className="mr-2 h-4 w-4" /> Add Webhook</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Webhook</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>URL</Label>
                  <Input
                    value={newWebhook.url}
                    onChange={e => setNewWebhook(prev => ({ ...prev, url: e.target.value }))}
                    placeholder="https://example.com/webhook"
                  />
                  {detectWebhookType(newWebhook.url) === "teams" && (
                    <div className="flex items-start space-x-2">
                      <Checkbox
                        id="webhook-send-json"
                        checked={newWebhook.webhook_type === "generic"}
                        onCheckedChange={checked =>
                          setNewWebhook(prev => ({ ...prev, webhook_type: checked === true ? "generic" : undefined }))
                        }
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
                    value={newWebhook.secret} 
                    onChange={e => setNewWebhook(prev => ({ ...prev, secret: e.target.value }))}
                    type="password"
                  />
                </div>
              <div className="space-y-2">
                <Label>Events</Label>
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {availableEvents.map(event => (
                    <div key={event.id} className="flex items-start space-x-2">
                      <Checkbox
                        id={event.id}
                        checked={(newWebhook.events || []).includes(event.id)}
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
              <Button onClick={handleCreate} className="w-full" disabled={!newWebhook.url || newWebhook.events.length === 0}>Create Webhook</Button>
            </div>
          </DialogContent>
        </Dialog>
        )}
      </CardHeader>
      <CardContent>
        <Table className="table-fixed">
          <TableHeader>
            <TableRow>
              <TableHead className="w-auto">URL</TableHead>
              <TableHead className="w-[90px]">Type</TableHead>
              <TableHead className="w-[100px]">Status</TableHead>
              <TableHead className="w-[200px]">Events</TableHead>
              <TableHead className="w-[150px]">Created At</TableHead>
              <TableHead className="w-[90px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {webhooks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  No webhooks configured
                </TableCell>
              </TableRow>
            ) : (
              webhooks.map(webhook => (
                <TableRow key={webhook.id}>
                  <TableCell className="font-mono text-xs truncate max-w-0" title={webhook.url}>{webhook.url}</TableCell>
                  <TableCell>
                    <Badge variant={webhook.webhook_type && webhook.webhook_type !== "generic" ? "default" : "outline"}>
                      {TYPE_LABELS[webhook.webhook_type ?? "generic"]}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {isFailing(webhook) ? (
                      <Badge variant="destructive" title={`Last failed delivery: ${formatDateTime(webhook.last_failure_at)}`}>
                        Failing
                      </Badge>
                    ) : webhook.last_triggered_at ? (
                      <Badge variant="outline" title={`Last delivery: ${formatDateTime(webhook.last_triggered_at)}`}>
                        Delivered
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">No deliveries yet</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap">
                      {(webhook.events || []).map(e => (
                        <Badge key={e} variant="secondary">{e}</Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>{formatDate(webhook.created_at)}</TableCell>
                  <TableCell>
                    <div className="flex">
                      {canTest && (
                        <Button variant="ghost" size="icon" aria-label="Send test" title="Send test" onClick={() => handleTest(webhook.id)}>
                          <Send className="h-4 w-4" />
                        </Button>
                      )}
                      {canDeleteWh && (
                        <Button variant="ghost" size="icon" onClick={() => handleDelete(webhook.id)}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
