import { useState } from "react"
import { Webhook, WebhookCreate } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { Trash2, Plus } from "lucide-react"
import { toast } from "sonner"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuth } from "@/context/AuthContext"

interface WebhookManagerProps {
  webhooks: Webhook[]
  isLoading: boolean
  onCreate: (data: WebhookCreate) => Promise<Webhook>
  onDelete: (id: string) => Promise<void>
  title?: string
  description?: string
  createPermission?: string
  deletePermission?: string
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
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const { hasPermission } = useAuth()
  const [newWebhook, setNewWebhook] = useState<WebhookCreate>({
    url: "",
    events: [],
    secret: ""
  })

  const availableEvents = [
    { id: "scan_completed", label: "Scan Completed" },
    { id: "vulnerability_found", label: "Vulnerability Found" }
  ]

  const handleCreate = async () => {
    try {
      await onCreate(newWebhook)
      setIsCreateOpen(false)
      setNewWebhook({ url: "", events: [], secret: "" })
      toast.success("Webhook created")
    } catch (error) {
      toast.error("Failed to create webhook")
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await onDelete(id)
      toast.success("Webhook deleted")
    } catch (error) {
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
        {hasPermission(createPermission) && (
          <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
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
                <div className="space-y-2">
                  {availableEvents.map(event => (
                    <div key={event.id} className="flex items-center space-x-2">
                      <Checkbox 
                        id={event.id} 
                        checked={newWebhook.events.includes(event.id)}
                        onCheckedChange={() => toggleEvent(event.id)}
                      />
                      <Label htmlFor={event.id}>{event.label}</Label>
                    </div>
                  ))}
                </div>
              </div>
              <Button onClick={handleCreate} className="w-full">Create Webhook</Button>
            </div>
          </DialogContent>
        </Dialog>
        )}
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>URL</TableHead>
              <TableHead>Events</TableHead>
              <TableHead>Created At</TableHead>
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
                  <TableCell className="font-mono text-xs">{webhook.url}</TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap">
                      {webhook.events.map(e => (
                        <span key={e} className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                          {e}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>{new Date(webhook.created_at).toLocaleDateString()}</TableCell>
                  <TableCell>
                    {hasPermission(deletePermission) && (
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
