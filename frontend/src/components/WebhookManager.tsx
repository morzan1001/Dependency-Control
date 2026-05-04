import { useState } from "react"
import { Webhook, WebhookCreate } from "@/types/webhook"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"
import { Trash2, Plus } from "lucide-react"
import { toast } from "sonner"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuth } from "@/context/useAuth"
import { useDialogState } from "@/hooks/use-dialog-state"
import { formatDate } from "@/lib/utils"

interface WebhookManagerProps {
  readonly webhooks: Webhook[]
  readonly isLoading: boolean
  readonly onCreate: (data: WebhookCreate) => Promise<Webhook>
  readonly onDelete: (id: string) => Promise<void>
  readonly title?: string
  readonly description?: string
  readonly createPermission?: string | boolean
  readonly deletePermission?: string | boolean
}

export function WebhookManager({ 
  webhooks, 
  isLoading, 
  onCreate, 
  onDelete, 
  title = "Webhooks", 
  description = "Manage webhooks for event notifications.",
  createPermission = "webhook:create",
  deletePermission = "webhook:delete"
}: WebhookManagerProps) {
  const createDialog = useDialogState()
  const { hasPermission } = useAuth()
  const canCreate = typeof createPermission === 'boolean'
    ? createPermission
    : hasPermission(createPermission)
  const canDeleteWh = typeof deletePermission === 'boolean'
    ? deletePermission
    : hasPermission(deletePermission)
  const [newWebhook, setNewWebhook] = useState<WebhookCreate>({
    url: "",
    events: [],
    secret: ""
  })

  // Back-compat: legacy snake_case event names mapped to canonical dot-notation.
  const EVENT_ALIASES: Record<string, string> = {
    scan_completed: "scan.completed",
    vulnerability_found: "vulnerability.found",
    analysis_failed: "analysis.failed",
  }
  const canonicalize = (eventId: string): string => EVENT_ALIASES[eventId] ?? eventId

  const availableEvents = [
    {
      id: "scan.completed",
      label: "Scan completed",
      description: "Fires when a project scan finishes successfully.",
    },
    {
      id: "vulnerability.found",
      label: "Vulnerability found",
      description: "Fires when a new vulnerability is detected in a scan.",
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
      description: "Fires when a compliance report completes successfully.",
    },
    {
      id: "pqc_migration_plan.generated",
      label: "PQC migration plan generated",
      description: "Fires when a post-quantum migration plan is produced.",
    },
  ]

  const handleCreate = async () => {
    if (!newWebhook.url || newWebhook.events.length === 0) return
    try {
      const payload: WebhookCreate = {
        url: newWebhook.url,
        events: newWebhook.events,
        ...(newWebhook.secret ? { secret: newWebhook.secret } : {}),
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
                        checked={(newWebhook.events || []).some(e => canonicalize(e) === event.id)}
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
              <TableHead className="w-[200px]">Events</TableHead>
              <TableHead className="w-[150px]">Created At</TableHead>
              <TableHead className="w-[50px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {webhooks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground">
                  No webhooks configured
                </TableCell>
              </TableRow>
            ) : (
              webhooks.map(webhook => (
                <TableRow key={webhook.id}>
                  <TableCell className="font-mono text-xs truncate max-w-0" title={webhook.url}>{webhook.url}</TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap">
                      {(webhook.events || []).map(e => (
                        <Badge key={e} variant="secondary">{canonicalize(e)}</Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>{formatDate(webhook.created_at)}</TableCell>
                  <TableCell>
                    {canDeleteWh && (
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(webhook.id)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    )}
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
