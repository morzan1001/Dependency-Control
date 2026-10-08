import { useState } from "react"
import { Webhook, WebhookCreate, WebhookType, WebhookUpdate } from "@/types/webhook"
import { webhookApi } from "@/api/webhooks"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogTrigger } from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { WebhookForm } from "@/components/WebhookForm"
import { Trash2, Plus, Send, Pencil } from "lucide-react"
import { toast } from "sonner"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuth } from "@/context/useAuth"
import { useDialogState } from "@/hooks/use-dialog-state"
import { formatDate, formatDateTime, getErrorMessage } from "@/lib/utils"

const TYPE_LABELS: Record<WebhookType, string> = { generic: "Generic", teams: "Teams", slack: "Slack" };

// The server stamps last_triggered_at on success and last_failure_at on failure, so the later one is the current state.
function isFailing(webhook: Webhook): boolean {
  if (!webhook.last_failure_at) return false;
  return !webhook.last_triggered_at || Date.parse(webhook.last_failure_at) > Date.parse(webhook.last_triggered_at);
}

function DeliveryState({ webhook }: { readonly webhook: Webhook }) {
  if (!webhook.is_active) {
    return <Badge variant="secondary" title="Receives no deliveries while paused">Paused</Badge>
  }
  if (isFailing(webhook)) {
    return (
      <Badge variant="destructive" title={`Last failed delivery: ${formatDateTime(webhook.last_failure_at)}`}>
        Failing
      </Badge>
    )
  }
  if (webhook.last_triggered_at) {
    return (
      <Badge variant="outline" title={`Last delivery: ${formatDateTime(webhook.last_triggered_at)}`}>
        Delivered
      </Badge>
    )
  }
  return <span className="text-xs text-muted-foreground">No deliveries yet</span>
}

interface WebhookManagerProps {
  readonly webhooks: Webhook[]
  readonly isLoading: boolean
  readonly onCreate: (data: WebhookCreate) => Promise<Webhook>
  readonly onUpdate: (id: string, data: WebhookUpdate) => Promise<Webhook>
  readonly onDelete: (id: string) => Promise<void>
  readonly title?: string
  readonly description?: string
  readonly createPermission?: string | boolean
  readonly deletePermission?: string | boolean
  readonly updatePermission?: string | boolean
}

export function WebhookManager({ 
  webhooks, 
  isLoading, 
  onCreate, 
  onUpdate,
  onDelete, 
  title = "Webhooks", 
  description = "Manage webhooks for event notifications.",
  createPermission = "webhook:create",
  deletePermission = "webhook:delete",
  updatePermission = "webhook:update"
}: WebhookManagerProps) {
  const createDialog = useDialogState()
  const [editing, setEditing] = useState<Webhook | null>(null)
  const { hasPermission } = useAuth()
  const canCreate = typeof createPermission === 'boolean'
    ? createPermission
    : hasPermission(createPermission)
  const canDeleteWh = typeof deletePermission === 'boolean'
    ? deletePermission
    : hasPermission(deletePermission)
  const canUpdate = typeof updatePermission === 'boolean'
    ? updatePermission
    : hasPermission(updatePermission)

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
            <WebhookForm onCreate={onCreate} onSaved={createDialog.closeDialog} />
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
              <TableHead className="w-[140px]"></TableHead>
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
                    <DeliveryState webhook={webhook} />
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
                      {canUpdate && (
                        <>
                          <Button variant="ghost" size="icon" aria-label="Edit webhook" title="Edit webhook" onClick={() => setEditing(webhook)}>
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button variant="ghost" size="icon" aria-label="Send test" title="Send test" onClick={() => handleTest(webhook.id)}>
                            <Send className="h-4 w-4" />
                          </Button>
                        </>
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
        {editing && (
          <Dialog open onOpenChange={() => setEditing(null)}>
            <WebhookForm
              webhook={editing}
              onUpdate={data => onUpdate(editing.id, data)}
              onSaved={() => setEditing(null)}
            />
          </Dialog>
        )}
      </CardContent>
    </Card>
  )
}
